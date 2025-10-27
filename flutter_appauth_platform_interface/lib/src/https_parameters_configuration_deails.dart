mixin HttpsParametersConfigurationDetails {
  bool allowInsecureConnections = false;
  String customCaCertificates = "";
  bool includePublicRootCaCertificates = true;

  void setHttpsParameters(bool allowInsecureConnections, String customCaCertificates, bool includePublicRootCaCertificates) {
    this.allowInsecureConnections = allowInsecureConnections;
    this.customCaCertificates = customCaCertificates;
    this.includePublicRootCaCertificates = includePublicRootCaCertificates;
  }
}
