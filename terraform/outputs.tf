output "cloudguard_url" {
  description = "Live URL of the deployed CloudGuard Cloud Run service"
  value       = google_cloud_run_v2_service.cloudguard.uri
}

output "service_account_email" {
  description = "Email of the CloudGuard runner service account"
  value       = google_service_account.cloudguard_runner.email
}

output "artifact_registry_repo" {
  description = "Artifact Registry repository URI"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/cloudguard/cloudguard"
}
