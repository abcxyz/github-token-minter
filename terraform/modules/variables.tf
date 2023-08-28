variable "project_id" {
  description = "The Google Cloud project ID for these resources."
  type        = string
  validation {
    condition     = length(var.project_id) <= 30
    error_message = "ERROR: project_id must be <= 30 characters."
  }
}

variable "id" {
  description = "An ID for these resources."
  type        = string
  validation {
    condition     = length(var.id) <= 22
    error_message = "ERROR: id must be 22 characters or less."
  }
}

variable "github" {
  description = "The GitHub repository information."
  type = object({
    owner_name     = string
    owner_id       = string
    repo_name      = string
    repo_id        = string
    default_branch = optional(string, "main")
  })
}

variable "wif_attribute_mapping" {
  type        = map(string)
  description = "(Optional) Workload Identity Federation provider attribute mappings. Defaults to base mapping for default attribute condition."
  default     = null
}

variable "wif_attribute_condition" {
  type        = string
  description = "(Optional) Workload Identity Federation provider attribute condition. Appended to base condition, matching GitHub owner and repository id. Defaults to preventing `pull_request_target` event and matching GitHub owner and repository id."
  default     = null
}
