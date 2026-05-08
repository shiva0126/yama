package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"ad-assessment/defense-shared/config"
	"ad-assessment/defense-shared/events"
	"ad-assessment/defense-shared/messaging"
	"ad-assessment/defense-shared/server"
	"ad-assessment/defense-shared/storage"
	"ad-assessment/defense-shared/store"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func main() {
	cfg := config.Load("evidence-ledger", "8096", "9096")
	pool, err := storage.Open(context.Background(), cfg.DBDSN)
	if err != nil {
		log.Fatalf("open db pool: %v", err)
	}
	defer pool.Close()

	mc, err := minio.New(cfg.MinIOEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinIOAccessKey, cfg.MinIOSecretKey, ""),
		Secure: false,
	})
	if err != nil {
		log.Fatalf("minio client: %v", err)
	}

	// Ensure bucket exists
	ctx := context.Background()
	exists, err := mc.BucketExists(ctx, cfg.MinIOBucket)
	if err != nil {
		log.Printf("minio bucket check: %v — uploads will fail until resolved", err)
	} else if !exists {
		if err := mc.MakeBucket(ctx, cfg.MinIOBucket, minio.MakeBucketOptions{}); err != nil {
			log.Printf("minio make bucket: %v", err)
		} else {
			log.Printf("created MinIO bucket: %s", cfg.MinIOBucket)
		}
	}

	nc, js, err := messaging.Connect(cfg.NATSURL)
	if err != nil {
		log.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	if err := messaging.EnsureDefenseStream(js); err != nil {
		log.Fatalf("ensure stream: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.HealthHandler(cfg.ServiceName))

	mux.HandleFunc("/evidence/bundle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			server.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}

		var bundle events.EvidenceBundle
		if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		finalized, uploadErr := finalizeAndStore(r.Context(), mc, cfg.MinIOBucket, bundle)
		if uploadErr != nil {
			log.Printf("evidence store: %v", uploadErr)
		}

		if _, err := store.SaveEvidenceBundle(r.Context(), pool, finalized); err != nil {
			log.Printf("persist evidence bundle: %v", err)
		}
		if err := messaging.PublishJSON(r.Context(), js, messaging.SubjectEvidenceEvents, finalized); err != nil {
			log.Printf("publish evidence bundle: %v", err)
		}
		server.WriteJSON(w, http.StatusOK, finalized)
	})

	mux.HandleFunc("/evidence", func(w http.ResponseWriter, r *http.Request) {
		rows, err := pool.Query(r.Context(), `
			SELECT id, incident_id, storage_key, sha256, content_type, size_bytes, created_at
			FROM   defense_evidence_bundles
			ORDER  BY created_at DESC
			LIMIT  100
		`)
		if err != nil {
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		var bundles []map[string]any
		for rows.Next() {
			var id, storageKey, sha256 string
			var incidentID, contentType *string
			var sizeBytes *int64
			var createdAt time.Time
			rows.Scan(&id, &incidentID, &storageKey, &sha256, &contentType, &sizeBytes, &createdAt)
			bundles = append(bundles, map[string]any{
				"id": id, "incident_id": incidentID, "storage_key": storageKey,
				"sha256": sha256, "content_type": contentType, "size_bytes": sizeBytes,
				"created_at": createdAt,
			})
		}
		if bundles == nil {
			bundles = []map[string]any{}
		}
		server.WriteJSON(w, http.StatusOK, map[string]any{"bundles": bundles, "total": len(bundles)})
	})

	log.Printf("%s listening on :%s", cfg.ServiceName, cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, mux))
}

func finalizeAndStore(ctx context.Context, mc *minio.Client, bucket string, bundle events.EvidenceBundle) (events.EvidenceBundle, error) {
	if bundle.ID == "" {
		bundle.ID = uuid.NewString()
	}
	if bundle.ContentType == "" {
		bundle.ContentType = "application/json"
	}

	raw, _ := json.Marshal(bundle.Metadata)
	sum := sha256.Sum256(raw)
	bundle.SHA256 = hex.EncodeToString(sum[:])

	if bundle.StorageKey == "" {
		bundle.StorageKey = fmt.Sprintf("evidence/%s/%s.json",
			time.Now().UTC().Format("2006/01/02"),
			bundle.ID,
		)
	}

	// Upload the bundle metadata payload to MinIO
	payload, _ := json.MarshalIndent(bundle, "", "  ")
	bundle.SizeBytes = int64(len(payload))

	_, err := mc.PutObject(ctx, bucket, bundle.StorageKey, bytes.NewReader(payload), int64(len(payload)),
		minio.PutObjectOptions{ContentType: bundle.ContentType},
	)
	if err != nil {
		return bundle, fmt.Errorf("minio upload %s: %w", bundle.StorageKey, err)
	}

	log.Printf("evidence uploaded: bucket=%s key=%s size=%d sha256=%s",
		bucket, bundle.StorageKey, bundle.SizeBytes, bundle.SHA256)
	return bundle, nil
}
