variable "admin_ip" {
  default = "211.244.58.127/32"
}

variable "mina_ip" {
  default = "210.97.74.152/32"
}

variable "alert_email" {
  default = "yun090405@gmail.com"
}

variable "account_id" {
  default = "969779760570"
}

variable "key_pair_name" {
  default = "team5-key"
}

variable "discord_webhook_url" {
  description = "Discord Webhook URL for security alerts"
  sensitive   = true
}
