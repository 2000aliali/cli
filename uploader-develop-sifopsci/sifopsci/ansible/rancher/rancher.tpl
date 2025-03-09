apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: rancher
  labels:
    app: rancher
    chart: rancher-2.5.11
    heritage: Helm
    release: rancher
  annotations:
    #cert-manager.io/issuer: rancher
    #cert-manager.io/issuer-kind: Issuer
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "30"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
spec:
  rules:
  - host: rancher.hadithm6.ma  # hostname to access rancher server
    http:
      paths:
      - backend:
          serviceName: rancher
          servicePort: 80
  tls:
  - hosts:
    - rancher.hadithm6.ma
    secretName: certificates-secret
