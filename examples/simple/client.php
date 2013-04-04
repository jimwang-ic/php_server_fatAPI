<?php
// Include Composer-generated autoloader
require(__DIR__.'/../../vendor/autoload.php');

$loop = new React\EventLoop\StreamSelectLoop();

// Connect to DNode server running in port 7070 and call Zing with argument 33
$dnode = new DNode\DNode($loop);
$dnode->connect(8080, function($remote, $connection) {
    $remote->zing(33, function($n) use ($connection) {
        echo "n = {$n}\n";
        $connection->end();
    });
});

$loop->run();
