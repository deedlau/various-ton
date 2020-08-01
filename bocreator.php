<?php

require_once './utils.php';
require_once './sodium_compat-1.13.0/autoload.php';

/**
 * Prepares submitTransaction message BOC for SafeMultisigWallet/SetcodeMultisigWallet wallet smart-contracts of TONLabs in pure PHP
 * 
 * @param string $senderAddr Address of funds sender wallet in the form of '0:4810d68c1607e44ac452961f195af81f93ad885beb90c7f5bac35182df6536f8'
 * @param string $receiverAddr Address of funds receiver wallet in the form of '0:4810d68c1607e44ac452961f195af81f93ad885beb90c7f5bac35182df6536f8'
 * @param int $amount Tokens amount to send, in nanotokens
 * @param string $senderPrivKeySeed Sender wallet custodian Ed25519 private key seed (i.e. 'private' value from multisig.keys.json file of tonos-cli)
 * @param bool $bounce Whether to bounce the transaction of the destination address does not exist (set to false if you need to create that address)
 * @param bool $allBalance Whether to transfer all funds from the sender wallet to the receiver wallet (does not implemented properly in smart-contract code yet)
 * @param int $messageTimestamp Timestamp of external message creation for the wallet (UNIX milliseconds UTC), if set to 0 current timestamp is used
 * @param int $expire Message expiration period
 * @return string Raw binary BOC contents which can be uploaded to TON network via lite-client (sendfile), FreeTON GraphQL, etc.
 */
function create_submitTransaction_boc($senderAddr, $receiverAddr, $amount, $senderPrivKeySeed, $bounce = true, $allBalance = false, $messageTimestamp = 0, $expire = 0xFFFFFFFF)
{
	assert($amount >= 0 && $amount <= pow(2, 128));
	assert(strlen($senderPrivKeySeed) == 64);
	assert(ctype_xdigit($senderPrivKeySeed));
	assert($expire >= 0 && $expire <= 0xFFFFFFFF);
	
	if ($messageTimestamp <= 0)
	{
		$messageTimestamp = get_unix_timestamp_ms();
	}
	
	list($senderWcPart, $senderAddrPart) = split_wallet_addr($senderAddr);
	list($receiverWcPart, $receiverAddrPart) = split_wallet_addr($receiverAddr);
	
	$senderWcPartUnsignedChar = intval($senderWcPart, 10) & 0xFF; // two's complement automatically
	$receiverWcPartUnsignedChar = intval($receiverWcPart, 10) & 0xFF;
	
	// cell 3 (last one)
	$cell3Header = "\x00\x00"; // d1, d2 of a cell: level 0, without hashes, not exotic, no references, not absent, data size is 0, no completion tag
	$cell3Contents = ''; // no data, empty cell
	$cell3References = ''; // no references
	$cell3Data = $cell3Header . $cell3Contents . $cell3References;
	
	// cell 2, submitTransaction call params
	$cell2Header = "\x01\x63"; // d1, d2 of a cell: level 0, without hashes, not exotic, 1 reference, not absent, data size is 50, completion tag is present
	
	$cell2ContentsBin = '100'; // unk1, 3 bits
	$cell2ContentsBin .= str_pad(decbin($receiverWcPartUnsignedChar), 8, '0', STR_PAD_LEFT); // receiver wallet address workchain, 8 bits, 'dest' value part in submitTransaction call
	$cell2ContentsBin .= hex_s_to_bin_s($receiverAddrPart); // receiver wallet address address, 256 bits, 'dest' value part in submitTransaction call
	$cell2ContentsBin .= str_pad(decbin($amount), 128, '0', STR_PAD_LEFT); // value to send in nanotokens, 128 bits, 'value' value in submitTransaction call
	$cell2ContentsBin .= $bounce ? '1' : '0'; // bounce flag, 1 bit, 'bounce' value in submitTransaction call
	$cell2ContentsBin .= $allBalance ? '1' : '0'; // all balance transfer flag, 1 bit, 'allBalance' value in submitTransaction call
	$cell2ContentsBin .= '100'; // unk2, 3 bits
	$cell2Contents = bin_s_to_raw($cell2ContentsBin);
	
	$cell2References = "\x03"; // reference to cell 3
	$cell2Data = $cell2Header . $cell2Contents . $cell2References;
	
	// let's make a Ed25519 signature first, let's partially construct cell 1 contents (second half of it, excluding the signature)
	$senderKeyPair = ParagonIE_Sodium_Compat::crypto_sign_seed_keypair(hex2bin($senderPrivKeySeed));
	$senderKeyPub = ParagonIE_Sodium_Compat::crypto_sign_publickey($senderKeyPair);
	$senderKeyPrivPub = ParagonIE_Sodium_Compat::crypto_sign_secretkey($senderKeyPair);
	/* DEBUG
	echo 'Sender keypair: ', bin2hex($senderKeyPub), ', ', substr(bin2hex($senderKeyPrivPub), 0, 64), PHP_EOL;
	*/
	
	$cell1ContentsPartBin = '1'; // unk2, 1 bit
	$cell1ContentsPartBin .= raw_to_bin_s($senderKeyPub); // sender's pubkey (the signing key), 256 bits
	$cell1ContentsPartBin .= str_pad(decbin($messageTimestamp), 64, '0', STR_PAD_LEFT); // message creation unix timestamp (UTC), milliseconds, 64 bits
	$cell1ContentsPartBin .= str_pad(decbin($expire), 32, '0', STR_PAD_LEFT); // message expire time, 32 bits (32-bit UINT_MAX by default)
	$cell1ContentsPartBin .= str_pad(decbin(0x131D82CD), 32, '0', STR_PAD_LEFT); // calling wallet method id, 32 bits (0x131D82CD for submitTransaction, 0x4CEE646C for sendTransaction)
	$cell1ContentsPartBin .= '100000'; // unk3, 6 bits
	
	$cell1ContentsPartForSigningBin = $cell1ContentsPartBin;
	$cell1ContentsPartForSigningBin .= '0'; // additional '0' at the end, 1 bit
	$cell1ContentsPartForSigning = bin_s_to_raw($cell1ContentsPartForSigningBin);
	$cell1HeaderForSigning = "\x01\x61";  // d1, d2 of a cell
	$cell1ContentsForSigning = $cell1HeaderForSigning . $cell1ContentsPartForSigning;
	
	// here we go with SHA256-hashing cell contents
	$cell3Hash = hex2bin(hash('sha256', $cell3Header . $cell3Contents)); // hash of cell 3 contents without references
	$cell2Hash = hex2bin(hash('sha256', $cell2Header . $cell2Contents . $cell3Header . $cell3Hash)); // hash of cell 2 contents + cell 3 contents hash
	$cell1Hash = hex2bin(hash('sha256', $cell1ContentsForSigning . "\x00\x01" . $cell2Hash)); // hash of cell1 partial contents + cell 2 contents hash with somewhat different header
	
	// here we go with Ed25519-signing of the above hash
	$cell1Signature = ParagonIE_Sodium_Compat::crypto_sign_detached($cell1Hash, $senderKeyPrivPub);
	
	
	// cell 1
	$cell1Header = "\x01\xe1"; // d1, d2 of a cell: level 0, without hashes, not exotic, 1 reference, not absent, data size is 225, completion tag is present
	
	$cell1ContentsBin = '1'; // unk1, 1 bit
	$cell1ContentsBin .= raw_to_bin_s($cell1Signature); // signature (Ed25519) from data above, 512 bit
	$cell1ContentsBin .= $cell1ContentsPartBin;
	
	$cell1Contents = bin_s_to_raw($cell1ContentsBin);
	$cell1References = "\x02"; // reference to cell 2
	$cell1Data = $cell1Header . $cell1Contents . $cell1References;
	
	// cell 0 (first one)
	
	$cell0Header = "\x01\x45"; // d1, d2 of a cell: level 0, without hashes, not exotic, 1 reference, not absent, data size is 35, completion tag is present
	
	$cell0ContentsBin = '1000100'; // unk1, 7 bits
	$cell0ContentsBin .= str_pad(decbin($senderWcPartUnsignedChar), 8, '0', STR_PAD_LEFT); // sender wallet address workchain, 8 bits
	$cell0ContentsBin .= hex_s_to_bin_s($senderAddrPart); //  sender wallet address address, 256 bits
	$cell0ContentsBin .= '000001100'; // unk2, 9 bits
	
	$cell0Contents = bin_s_to_raw($cell0ContentsBin);
	$cell0References = "\x01"; // reference to cell 1
	$cell0Data = $cell0Header . $cell0Contents . $cell0References;
	
	$bocData = "\xb5\xee\x9c\x72"; // magic of serialized_boc
	$bocData .= "\x41"; // first byte: has_idx = false, has_crc32c = true, has_cache_bits = false, flags = 0, size = 1
	$bocData .= "\x04"; // off_bytes = 4
	$bocData .= "\x04"; // cells = 4
	$bocData .= "\x01"; // roots = 1
	$bocData .= "\x00"; // absent = 0
	$bocData .= pack('N', strlen($cell0Data . $cell1Data . $cell2Data . $cell3Data)); // tot_cells_size = 209 (maybe hardcode as "\x00\x00\x00\xd1")
	$bocData .= "\x00"; // root_list = [0]
	
	$bocData .= $cell0Data;
	$bocData .= $cell1Data;
	$bocData .= $cell2Data;
	$bocData .= $cell3Data;
	
	$bocData .= pack('V', crc32c_string($bocData)); // crc32c of data
	
	
	return $bocData;
}

?>


