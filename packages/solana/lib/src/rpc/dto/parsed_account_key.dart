import 'package:json_annotation/json_annotation.dart';
import 'package:solana/src/rpc/dto/account_key.dart';

part 'parsed_account_key.g.dart';

@JsonSerializable()
class ParsedAccountKey implements AccountKey {
  const ParsedAccountKey({
    required this.pubkey,
  });

  factory ParsedAccountKey.fromJson(Map<String, dynamic> json) =>
      _$ParsedAccountKeyFromJson(json);

  final String pubkey;
}
