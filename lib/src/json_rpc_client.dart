import 'dart:convert';

import 'package:crypto_please_solana_lib/src/types/accountInfo.dart';
import 'package:crypto_please_solana_lib/src/types/blockhash.dart';
import 'package:crypto_please_solana_lib/src/types/http_error.dart';
import 'package:crypto_please_solana_lib/src/types/json_rpc_response_object.dart';
import 'package:crypto_please_solana_lib/src/types/signature_statuses.dart';
import 'package:crypto_please_solana_lib/src/types/transfer_result.dart';
import 'package:crypto_please_solana_lib/src/types/tx_signature.dart';
import 'package:http/http.dart' as http;

class JsonRpcClient {
  JsonRpcClient(this._url);

  final String _url;
  int lastId = 1;

  // Map constructors for known types
  static final _constructors = {
    Blockhash: (String jsonString) =>
        Blockhash.fromJsonRpcResponseString(jsonString),
    AccountInfo: (String jsonString) =>
        AccountInfo.fromJsonRpcResponseString(jsonString),
    SimulateTxResult: (String jsonString) =>
        SimulateTxResult.fromJsonRpcResponseString(jsonString),
    TxSignature: (String jsonString) =>
        TxSignature.fromJsonRpcResponseString(jsonString),
    SignatureStatuses: (String jsonString) =>
        SignatureStatuses.fromJsonRpcResponseString(jsonString),
    String: JsonRpcResponseObject.getValue,
    int: JsonRpcResponseObject.getValue,
    BigInt: JsonRpcResponseObject.getValueAsBigInt,
  };

  T _handleResponse<T>(String jsonRpc2ResponseString) {
    if (_constructors[T] != null) {
      return _constructors[T](jsonRpc2ResponseString);
    } else {
      return null;
    }
  }

  /// Calls the [method] jsonrpc-2.0 method with [params] parameters
  Future<T> call<T>(String method, {List<dynamic> params = null}) async {
    Map<String, dynamic> request = <String, dynamic>{
      'jsonrpc': '2.0',
      'id': (lastId++).toString(),
      'method': method,
    };
    // If no parameters were specified, skip this field
    if (params != null) request['params'] = params;
    // Perform the POST request
    final http.Response response = await http.post(
      Uri.parse(_url),
      headers: <String, String>{
        'Content-Type': 'application/json; charset=UTF-8',
      },
      body: json.encode(request),
    );
    // Handle the response
    if (response.statusCode != 200) {
      throw HttpError(response.statusCode, response.body);
    } else {
      return _handleResponse<T>(response.body);
    }
  }
}