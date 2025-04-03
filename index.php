<?php
require_once __DIR__ . '/src/Router/Router.php';
require_once __DIR__ . '/src/Service/FetchLogService.php';
require_once __DIR__ . '/src/Controller/LogsDecoderController.php';

$router = new Router();
$fetchLogService = new FetchLogService();
$logsDecoderController = new LogsDecoderController();


$router->addRoute('GET', '/fetch-logs', [$fetchLogService, 'fetchLogFile']);
$router->addRoute('GET', '/decode-logs', [$logsDecoderController, 'decodeFile']);
$router->addRoute('GET', '/analyze', [$logsDecoderController, 'analyzeLogs']);
$router->addRoute('GET', '/read', [$logsDecoderController, 'readDecodedFile']);
$router->addRoute('GET', '/analyzeIP', [$logsDecoderController, 'analyzeIp']);
$router->addRoute('GET', '/analyzeURL', [$logsDecoderController, 'analyzeUrlWithVirusTotal']);
$router->addRoute('GET', '/dashboard', [$logsDecoderController, 'showDashboard']);
$router->addRoute('GET', '/test', [$logsDecoderController, 'test']);
$router->addRoute('GET', '/flag', [$logsDecoderController, 'flag']);
$router->addRoute('GET', '/a', [$logsDecoderController, 'scan']);

$router->handleRequest();
?>