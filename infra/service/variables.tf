variable "region" {
  type    = string
  default = "us-east-2"
}

variable "image_tag" {
  description = "The tag of the image to deploy (set by make deploy-plan, or by CI)"
  type        = string
}

variable "scan_memory_mb" {
  description = "More memory also means more CPU on Lambda, so DistilBERT runs faster"
  type        = number
  default     = 3008 # the account maximum; at 2 GB a cold start took 19 s of API Gateway's 29
}

variable "scan_concurrency" {
  description = "At most this many scans at once: a cost and abuse cap (threat model rule 11). null = no reservation"
  type        = number
  default     = 5
}

variable "api_burst" {
  type    = number
  default = 10
}

variable "api_rate_per_second" {
  type    = number
  default = 5
}

variable "p95_alarm_ms" {
  type    = number
  default = 3000
}

variable "explanations_enabled" {
  description = "Turns on the queue trigger of the explanation worker. Off until Phase 6"
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "Where alarms are emailed (ALERT_EMAIL=... at plan time, not committed); empty = no email"
  type        = string
  default     = ""
}
