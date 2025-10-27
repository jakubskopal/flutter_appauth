import 'dart:io';

import 'package:flutter_appauth_platform_interface/src/https_parameters_configuration_deails.dart';

import 'authorization_parameters.dart';
import 'authorization_request.dart';
import 'authorization_service_configuration.dart';
import 'authorization_token_request.dart';
import 'common_request_details.dart';
import 'end_session_request.dart';
import 'grant_type.dart';
import 'token_request.dart';

extension X509ChannelSerializer on List<X509Certificate> {
  String toChannelString() {
    return map((cert) => cert.pem).join('|');
  }
}

Map<String, Object?> _convertCommonRequestDetailsToMap(
    CommonRequestDetails commonRequestDetails) {
  return <String, Object?>{
    'clientId': commonRequestDetails.clientId,
    'issuer': commonRequestDetails.issuer,
    'nonce': commonRequestDetails.nonce,
    'discoveryUrl': commonRequestDetails.discoveryUrl,
    'redirectUrl': commonRequestDetails.redirectUrl,
    'scopes': commonRequestDetails.scopes,
    'serviceConfiguration': commonRequestDetails.serviceConfiguration?.toMap(),
    'additionalParameters': commonRequestDetails.additionalParameters,
  }
  ..addAll(_convertHttpsParametersToMap(commonRequestDetails));
}

Map<String, Object?> _convertHttpsParametersToMap(
  HttpsParametersConfigurationDetails httpsParameters
) {
  return <String, Object?>{
    'allowInsecureConnections': httpsParameters.allowInsecureConnections,
    'customCaCertificates': httpsParameters.customCaCertificates,
    'includePublicRootCaCertificates': httpsParameters.includePublicRootCaCertificates,
  };
}

extension EndSessionRequestMapper on EndSessionRequest {
  Map<String, Object?> toMap() {
    return <String, Object?>{
      'idTokenHint': idTokenHint,
      'postLogoutRedirectUrl': postLogoutRedirectUrl,
      'state': state,
      'additionalParameters': additionalParameters,
      'issuer': issuer,
      'discoveryUrl': discoveryUrl,
      'serviceConfiguration': serviceConfiguration?.toMap(),
      'externalUserAgent': externalUserAgent?.index,
    }
    ..addAll(_convertHttpsParametersToMap(this));
  }
}

extension AuthorizationRequestParameters on AuthorizationRequest {
  Map<String, Object?> toMap() {
    return _convertAuthorizationParametersToMap(this)
      ..addAll(_convertCommonRequestDetailsToMap(this));
  }
}

extension AuthorizationServiceConfigurationMapper
    on AuthorizationServiceConfiguration {
  Map<String, Object?> toMap() {
    return <String, Object?>{
      'tokenEndpoint': tokenEndpoint,
      'authorizationEndpoint': authorizationEndpoint,
      'endSessionEndpoint': endSessionEndpoint,
    };
  }
}

extension TokenRequestMapper on TokenRequest {
  Map<String, Object?> toMap() {
    return _convertTokenRequestToMap(this);
  }
}

extension AuthorizationTokenRequestMapper on AuthorizationTokenRequest {
  Map<String, Object?> toMap() {
    return _convertTokenRequestToMap(this)
      ..addAll(_convertAuthorizationParametersToMap(this));
  }
}

Map<String, Object?> _convertTokenRequestToMap(TokenRequest tokenRequest) {
  return <String, Object?>{
    'clientSecret': tokenRequest.clientSecret,
    'refreshToken': tokenRequest.refreshToken,
    'authorizationCode': tokenRequest.authorizationCode,
    'grantType': _inferGrantType(tokenRequest),
    'codeVerifier': tokenRequest.codeVerifier,
  }..addAll(_convertCommonRequestDetailsToMap(tokenRequest));
}

String? _inferGrantType(TokenRequest tokenRequest) {
  if (tokenRequest.grantType != null) {
    return tokenRequest.grantType;
  }
  if (tokenRequest.refreshToken != null) {
    return GrantType.refreshToken;
  }
  if (tokenRequest.authorizationCode != null) {
    return GrantType.authorizationCode;
  }

  throw ArgumentError.value(
      null, 'grantType', 'Grant type not specified and cannot be inferred');
}

Map<String, Object?> _convertAuthorizationParametersToMap(
    AuthorizationParameters authorizationParameters) {
  return <String, Object?>{
    'loginHint': authorizationParameters.loginHint,
    'promptValues': authorizationParameters.promptValues,
    'externalUserAgent': authorizationParameters.externalUserAgent?.index,
    'responseMode': authorizationParameters.responseMode,
  };
}
