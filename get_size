<?php

$id = @$_GET["id"];
$id = preg_replace("/[^0-9]/", "", $id);
if ($id)
{
	$file = "/tmp/.samy.pktsize.$id";
	for ($i = 0; $i < 20; $i++)
	{
		if (file_exists($file))
		{
			$bytes = file_get_contents($file);
			#rename($file, $file . "." . time());
			print "set_bytes($bytes);\n";
			exit;
		}
		sleep(1);
	}
}
else
{
	print "console.log('must pass id');\n";
}
?>
