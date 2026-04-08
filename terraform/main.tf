terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ── Artifact Registry ────────────────────────────────────────────────────────

resource "google_artifact_registry_repository" "cloudguard" {
  repository_id = "cloudguard"
  location      = var.region
  format        = "DOCKER"
  description   = "CloudGuard container images"
}

# ── Service Account ──────────────────────────────────────────────────────────

resource "google_service_account" "cloudguard_runner" {
  account_id   = "cloudguard-runner"
  display_name = "CloudGuard Cloud Run SA"
  description  = "Least-privilege SA for CloudGuard — reads assets, writes BigQuery"
}

resource "google_project_iam_member" "asset_viewer" {
  project = var.project_id
  role    = "roles/cloudasset.viewer"
  member  = "serviceAccount:${google_service_account.cloudguard_runner.email}"
}

resource "google_project_iam_member" "bq_data_editor" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = "serviceAccount:${google_service_account.cloudguard_runner.email}"
}

resource "google_project_iam_member" "bq_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.cloudguard_runner.email}"
}

# ── Cloud Run ────────────────────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "cloudguard" {
  name     = "cloudguard"
  location = var.region

  template {
    service_account = google_service_account.cloudguard_runner.email

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/cloudguard/cloudguard:latest"

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }
  }
}

# Allow public access for portfolio demo (health + root endpoints are safe)
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.cloudguard.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
