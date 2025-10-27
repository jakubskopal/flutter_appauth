import 'package:flutter_appauth_platform_interface/src/https_parameters_configuration_deails.dart';
import 'accepted_authorization_service_configuration_details.dart';

class CommonRequestDetails
    with AcceptedAuthorizationServiceConfigurationDetails, HttpsParametersConfigurationDetails {
  /// The client id.
  late String clientId;

  /// The redirect URL.
  late String redirectUrl;

  /// The request scopes.
  List<String>? scopes;

  /// The nonce.
  String? nonce;

  /// Additional parameters to include in the request.
  Map<String, String>? additionalParameters;
}
