<?php

define('GRAPHQL_URL', 'https://net.ton.dev/graphql'); // GraphQL URL
define('TIMEOUT', 1*60*1000); // default message timeout, in milliseconds (added to current time); default value is 1 minute
define('SLEEPTIME', 3); // waiting time between requests, in seconds
define('MAX_TRIES', 100); // max try count before giving up

require_once './bocreator.php';
require_once './utils.php';

function get_last_message_id($ch, $walletAddr)
{
	$postData = "{\"operationName\":\"messages\",\"variables\":{\"filter\":{\"dst\":{\"eq\":\"$walletAddr\"}},\"orderBy\":[{\"path\":\"created_at\",\"direction\":\"DESC\"}],\"limit\":1},\"query\":\"query messages(\$filter: MessageFilter, \$orderBy: [QueryOrderBy], \$limit: Int, \$timeout: Float) {\\n  messages(filter: \$filter, orderBy: \$orderBy, limit: \$limit, timeout: \$timeout) {\\n    id\\n}\\n}\\n\"}";
	curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
	$result = json_decode(curl_exec($ch), true);
	return $result['data']['messages'][0]['id'];
}

if ($argc < 5)
{
	echo 'Usage: '.__FILE__." <source_wallet> <dest_vallet> <amount_tokens> <private_key_of_source_wallet>\n";
	echo "Example: 0:4810d68c1607e44ac452961f195af81f93ad885beb90c7f5bac35182df6536f8 0:b2f4ca14745ece3388acb389d50a025fef9d8483f8436f75bd9c76eacee07d40 1 56ac5c54b34d658275968d2689928fad28ad35ba4fad694c9964ea8097e33be3\n";
	exit(0);
}
else
{
	$srcWalletAddr = $argv[1];
	$dstWalletAddr = $argv[2];
	$amount = intval($argv[3]) * pow(10, 9);
	$privateKey = $argv[4];
}

$boc = create_submitTransaction_boc($srcWalletAddr, $dstWalletAddr, $amount, $privateKey);
$bocBase64 = base64_encode($boc);
$bocHash = hex2bin(hash('sha256', $boc));
$bocHashBase64 = base64_encode($bocHash);

echo "BOC (hex): ", bin2hex($boc), PHP_EOL;
echo "BOC (base64): $bocBase64\n";
echo "GraphQL ID (BOC SHA256): $bocHashBase64\n";

$bocFileName = uniqid(basename(__FILE__, '.php'), true) . '.boc';
file_put_contents("./$bocFileName", $boc);
echo "Saved to $bocFileName\n\n";

$ch = curl_init();
curl_setopt($ch, CURLOPT_VERBOSE, false);
curl_setopt($ch, CURLOPT_URL, GRAPHQL_URL);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json')); 
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$lastMessageIdBefore = get_last_message_id($ch, $srcWalletAddr);
echo "Last message ID to wallet before out transaction was: $lastMessageIdBefore\n";

// graphql is not caring that much about our messages, so we need to be patient here
for ($i = 1; $i <= MAX_TRIES; $i++) {

	$expireAtVal = intval(get_unix_timestamp_ms() + TIMEOUT);
	$postData = "{\"operationName\":\"postRequests\",\"variables\":{\"requests\":[{\"id\":\"$bocHashBase64\",\"body\":\"$bocBase64\",\"expireAt\":$expireAtVal}]},\"query\":\"mutation postRequests(\$requests: [Request]) {\\npostRequests(requests: \$requests)\\n}\\n\"}";

	echo "Sending transaction... ($i)\n";
	curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
	$result=curl_exec($ch);

	$lastMessageId = get_last_message_id($ch, $srcWalletAddr);

	if ($lastMessageId == $lastMessageIdBefore)
	{
		sleep(SLEEPTIME);
	}
	else
	{
		break;
	}
    
}

curl_close($ch);

if ($i < MAX_TRIES)
{
	echo "Success\n";
}
else
{
	echo "Failed\n";
}
?>
