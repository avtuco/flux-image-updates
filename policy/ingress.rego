package main

deny[msg] {
    input.kind == "Ingress"
    
    not input.metadata.annotations["appgw.ingress.kubernetes.io/use-private-ip"] == "true"
    
    msg := sprintf("Validation Failed: Ingress '%v', no use-private-ip", [input.metadata.name])
}