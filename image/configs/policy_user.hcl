path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "userpass/users/{{identity.entity.name}}" {
  capabilities = ["read"]
}
