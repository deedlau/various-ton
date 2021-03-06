<?php

// various helper functions

/**
 * Gets current UNIX timestamp (UTC) with milliseconds precision
 */
function get_unix_timestamp_ms()
{
	return microtime(true) * 1000;
}

/**
 * Checks wallet address sanity and split it into workchain and address itself
 */
function split_wallet_addr($walletaddr)
{
	list($wc, $addr) = explode(':', $walletaddr);
	assert($wc == '-1' || $wc == '0');
	assert(strlen($addr) == 64);
	assert(ctype_xdigit($addr));
	return array($wc, $addr);
}

/**
 * Converts string of hexadecimal digits to string of binary digits (i.e. "abcd" -> "1010101111001101") with byte-wise 0-padding
 */
function hex_s_to_bin_s($hexStr)
{
	$hexParts = str_split($hexStr, 2);
	$result = '';
	foreach($hexParts as $hexPart) {
		$result .= str_pad(base_convert($hexPart, 16, 2), 8, '0', STR_PAD_LEFT);
	}
	return $result;
}

/**
 * Converts string of binary digits to their raw values (i.e. "1010101111001101" -> "\xab\xcd"), expects byte-wise 0-padding
 */
function bin_s_to_raw($binary)
{
    $bytes = str_split($binary, 8);
    $result = '';
    foreach($bytes as $byte) {
		$result .= chr(bindec($byte));
	}
    return $result;    
}

/**
 * Converts raw string to the string of binary digits (i.e. "\xab\xcd" -> "1010101111001101") with byte-wise 0-padding, opposite to bin_s_to_raw
 */
function raw_to_bin_s($rawstr)
{
	$result = '';
	for($i = 0; $i < strlen($rawstr); $i++){
		$result .= str_pad(decbin(ord($rawstr[$i])), 8, '0', STR_PAD_LEFT);
	}
	return $result;

}

// https://www.php.net/manual/en/function.crc32.php#31832
$GLOBALS['__crc32_table']=array();
__crc32c_init_table();

function __crc32c_init_table() {
	// Castagnoli, CRC32-C
	$polynomial = 0x1EDC6F41;

	for($i=0;$i <= 0xFF;++$i) {
		$GLOBALS['__crc32_table'][$i]=(__crc32_reflect($i,8) << 24);
		for($j=0;$j < 8;++$j) {
			$GLOBALS['__crc32_table'][$i]=(($GLOBALS['__crc32_table'][$i] << 1) ^
				(($GLOBALS['__crc32_table'][$i] & (1 << 31))?$polynomial:0));
		}
		$GLOBALS['__crc32_table'][$i] = __crc32_reflect($GLOBALS['__crc32_table'][$i], 32);
	}
}

function __crc32_reflect($ref, $ch) {
	$value=0;
   
	for($i=1;$i<($ch+1);++$i) {
		if($ref & 1) $value |= (1 << ($ch-$i));
		$ref = (($ref >> 1) & 0x7fffffff);
	}
	return $value;
}

/**
 * Calculates CRC32-C checksum of the string
 */
function crc32c_string($text) {
	$crc=0xffffffff;
	$len=strlen($text);

	for($i=0;$i < $len;++$i) {
		$crc=(($crc >> 8) & 0x00ffffff) ^ $GLOBALS['__crc32_table'][($crc & 0xFF) ^ ord($text{$i})];
	}
	
	return $crc ^ 0xffffffff;
}


?>
