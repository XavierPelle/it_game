<?php
ini_set('memory_limit', '512M');

ini_set('display_errors', 0);  // Désactive l'affichage des erreurs
ini_set('log_errors', 1);      // Active l'enregistrement des erreurs dans un fichier
ini_set('error_log', '/chemin/vers/votre/fichier_de_log.log'); // Spécifie le chemin du fichier de log


class LogsDecoderController
{
    public function decodeFile()
    {
        $pcapFile = 'src/Logs/logs';
        $decodedFile = 'src/Logs/decoded_logs.txt';

        $output = shell_exec("tshark -r $pcapFile -V");

        file_put_contents($decodedFile, $output);

        echo "Le fichier a été décodé et enregistré dans : $decodedFile\n";
    }

    private function initializeData()
    {
        return [
            'ethernet_frames' => 0,
            'ipv4_frames' => 0,
            'udp_frames' => 0,
            'tcp_frames' => 0,
            'kerberos_frames' => 0,
            'nbns_queries' => 0,
            'broadcast_addresses' => 0,
            'logs_length' => 0,
            'src_addresses' => [],
            'dst_addresses' => [],
            'ethernet_sources' => [],
            'ethernet_dests' => [],
            'tcp_ports' => [],
            'dst_ports' => [],
            'kerberos_services' => [],
            'kerberos_realms' => [],
            'ssdp_frames'  => 0,
            'url' => [],
        ];
    }

    private function processLine($line, &$data)
    {

        if (strpos($line, "Ethernet II") !== false) {
            $data['ethernet_frames']++;
            if (preg_match('/Src: ([^\s,]+)/', $line, $matches)) {
                $source = rtrim(trim($matches[1]), ',');
                $data['ethernet_sources'][$source] = ($data['ethernet_sources'][$source] ?? 0) + 1;
            }
            if (preg_match('/Dst: ([^\s,]+)/', $line, $matches)) {
                $destination = rtrim(trim($matches[1]), ',');
                $data['ethernet_dests'][$destination] = ($data['ethernet_dests'][$destination] ?? 0) + 1;
            }
        }

        if (strpos($line, "Internet Protocol Version 4") !== false) {
            $data['ipv4_frames']++;
            if (preg_match('/Src: ([^\s,]+)/', $line, $matches)) {
                $source = rtrim(trim($matches[1]), ',');
                $data['src_addresses'][$source] = ($data['src_addresses'][$source] ?? 0) + 1;
            }
            if (preg_match('/Dst: ([^\s,]+)/', $line, $matches)) {
                $destination = rtrim(trim($matches[1]), ',');
                $data['dst_addresses'][$destination] = ($data['dst_addresses'][$destination] ?? 0) + 1;
            }
        }

        if (strpos($line, "User Datagram Protocol") !== false) {
            $data['udp_frames']++;
        }

        if (strpos($line, "Transmission Control Protocol") !== false) {
            $data['tcp_frames']++;
            if (preg_match('/Src Port: (\d+)/', $line, $matches)) {
                $port = trim($matches[1]);
                if ($port < 1024) {
                    $data['tcp_ports'][$port] = ($data['tcp_ports'][$port] ?? 0) + 1;
                }
            }
            if (preg_match('/Dst Port: (\d+)/', $line, $matches)) {
                $port = trim($matches[1]);
                if ($port < 1024) {
                    $data['dst_ports'][$port] = ($data['dst_ports'][$port] ?? 0) + 1;
                }
            }
        }

        if (preg_match('/CNameString:\s*([^,]+)/', $line, $matches)) {
            $cname = trim($matches[1]);

            if (preg_match('/^[a-z]+\.[a-z]+$/', $cname)) {
                $data['kerberos_services'][$cname] = ($data['kerberos_services'][$cname] ?? 0) + 1;
            } else if (preg_match('/^[a-z]+$/', $cname)) {
                $data['kerberos_services'][$cname] = ($data['kerberos_services'][$cname] ?? 0) + 1;
            }
        }

        if (preg_match('/realm:\s*([^,]+)/', $line, $matches)) {
            $realm = trim($matches[1]);
            $data['kerberos_realms'][$realm] = ($data['kerberos_realms'][$realm] ?? 0) + 1;
        }

        if (strpos($line, "MS KRB5")) {
            $data['kerberos_frames']++;
        }

        if (strpos($line, "nbns") !== false) {
            $data['nbns_queries']++;
        }
        if (strpos($line, 'ssdp') !== false) {
            $data['ssdp_frames']++;
        }
        if (strpos($line, "Dst: Broadcast") !== false) {
            $data['broadcast_addresses']++;
        }
        if (strpos($line, "http://") !== false) {
            preg_match('/http:\/\/[^\s\[\]]+/', $line, $matches);

            if (!empty($matches)) {
                $url = $matches[0];
                if (strpos(strtolower($url), 'microsoft') === false && strpos(strtolower($url), 'windowsupdate') === false) {
                    $data['url'][$url] = ($data['url'][$url] ?? 0) + 1;
                }
            }
        }

        $data['logs_length']++;
    }

    public function analyzeIP()
    {
        if (!isset($_GET['ip'])) {
            echo "Aucune adresse IP fournie.";
            return;
        }

        $ip = $_GET['ip'];
        $vtApiKey = '168a3d3874c712ae9d6fc313ae20f0fbc44cbf6bc9f98a818302a05e5056163c';
        $abuseApiKey = '16ac9dfa2f6bec5ee41423b2ab52797178d1e576d7ab91be587f47adf4f9a45fbe761d9e470ceced';

        // ---- VIRUSTOTAL ----
        $vtUrl = 'https://www.virustotal.com/api/v3/ip_addresses/' . urlencode($ip);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $vtUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['x-apikey: ' . $vtApiKey]);
        $vtResponse = curl_exec($ch);
        curl_close($ch);

        $vtData = json_decode($vtResponse, true);
        $vtHtml = '';
        if (isset($vtData['data'])) {
            ob_start();
            echo "<h2>🔬 VirusTotal Analysis</h2>";
            echo "<table><tr><th>ID</th><td>{$vtData['data']['id']}</td></tr>";
            echo "<tr><th>Type</th><td>{$vtData['data']['type']}</td></tr></table>";
            echo "<h4>Tags</h4><ul>";
            foreach ($vtData['data']['attributes']['tags'] ?? [] as $tag) {
                echo "<li>{$tag}</li>";
            }
            echo "</ul>";
            echo "<h4>Last Analysis Stats</h4><ul>";
            foreach ($vtData['data']['attributes']['last_analysis_stats'] as $k => $v) {
                echo "<li><strong>" . ucfirst($k) . ":</strong> $v</li>";
            }
            echo "</ul>";
            $vtHtml = ob_get_clean();
        } else {
            $vtHtml = "<p>Aucune donnée VirusTotal disponible.</p>";
        }

        // ---- ABUSEIPDB ----
        $abuseComments = $this->getAbuseIpComments($ip, $abuseApiKey);
        ob_start();
        echo "<h2>🛡️ AbuseIPDB Reports</h2>";
        if (!empty($abuseComments)) {
            echo "<table><tr><th>Date</th><th>Pays</th><th>Catégories</th><th>Commentaire</th></tr>";
            foreach ($abuseComments as $entry) {
                echo "<tr><td>{$entry['date']}</td><td>{$entry['reporterCountryCode']}</td><td>" . implode(', ', $entry['categories']) . "</td><td>" . htmlentities($entry['comment']) . "</td></tr>";
            }
            echo "</table>";
        } else {
            echo "<p>Aucun commentaire ou rapport trouvé sur AbuseIPDB.</p>";
        }
        $abuseHtml = ob_get_clean();

        echo "<!DOCTYPE html><html lang='fr'><head><meta charset='UTF-8'><title>Analyse IP : $ip</title>
    <style>
        body { font-family: sans-serif; padding: 20px; background: #f9f9f9; }
        h2 { color: #2c3e50; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #fff; }
        th, td { padding: 10px; border: 1px solid #ccc; text-align: left; }
        th { background-color: #eee; }
        ul { list-style: disc; padding-left: 20px; }
    </style></head><body>";

        echo "<h1>Analyse complète pour l'IP : $ip</h1>";
        echo $vtHtml;
        echo $abuseHtml;
        echo "</body></html>";
    }

    function getAbuseIpComments($ip, $apiKey)
    {
        $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90&verbose=true";

        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTPHEADER => [
                "Key: $apiKey",
                "Accept: application/json"
            ],
        ]);

        $response = curl_exec($curl);
        curl_close($curl);

        $data = json_decode($response, true);

        // DEBUG POUR COMPRENDRE
        if (!$data || !isset($data['data'])) {
            echo "<p><strong>⚠️ Erreur : pas de champ 'data' dans la réponse AbuseIPDB.</strong></p>";
            echo "<pre>" . htmlentities($response) . "</pre>";
            return [];
        }

        if (!isset($data['data']['reports']) || !is_array($data['data']['reports'])) {
            echo "<p><strong> Aucun rapport trouvé (champ 'reports' absent ou vide).</strong></p>";
            return [];
        }

        $comments = [];
        foreach ($data['data']['reports'] as $report) {
            $comments[] = [
                'date' => $report['reportedAt'] ?? 'Inconnu',
                'comment' => $report['comment'] ?? '',
                'categories' => $report['categories'] ?? [],
                'reporterCountryCode' => $report['reporterCountryCode'] ?? '??'
            ];
        }

        return $comments;
    }

    public function analyzeUrlWithVirusTotal()
    {
        if (isset($_GET['urls'])) {
            $url = $_GET['urls'];
        } else {
            echo "Aucune adresse URL fournie.";
            return;
        }

        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            echo "L'URL fournie est invalide.";
            return;
        }

        $encodedUrl = rtrim(strtr(base64_encode($url), '+/', '-_'), '=');

        $apiKey = '168a3d3874c712ae9d6fc313ae20f0fbc44cbf6bc9f98a818302a05e5056163c';
        $apiUrl = "https://www.virustotal.com/api/v3/urls/{$encodedUrl}/comments";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $apiUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'x-apikey: ' . $apiKey,
            'accept: application/json',
        ]);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            echo 'Erreur cURL : ' . curl_error($ch);
            return;
        }
        curl_close($ch);

        $data = json_decode($response, true);

        if (isset($data['error'])) {
            echo "Erreur API : " . $data['error']['message'];
            return;
        }

        if (isset($data['data']) && !empty($data['data'])) {
            echo "<!DOCTYPE html><html lang='fr'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>Analyse de l'URL</title><style>
                    body { font-family: 'Roboto', sans-serif; background-color: #e5e5e5; margin: 0; padding: 0; }
                    h1, h2 { color: #333; }
                    .container { max-width: 80%; margin: 20px auto; background-color: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1); }
                    .header { display: flex; align-items: center; justify-content: center; padding: 20px 0; }
                    .header h1 { margin: 0; font-size: 24px; color: #0073e6; }
                    .header img { max-height: 40px; margin-right: 15px; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }
                    th, td { padding: 10px 15px; text-align: left; border: 1px solid #ddd; word-wrap: break-word; }
                    th { background-color: #f5f5f5; color: #333; font-weight: bold; }
                    tr:nth-child(even) { background-color: #fafafa; }
                    tr:hover { background-color: #f0f0f0; }
                    .badge { padding: 5px 10px; border-radius: 15px; color: white; font-weight: bold; }
                    .malicious { background-color: #f44336; }
                    .suspicious { background-color: #ff9800; }
                    .undetected { background-color: #4caf50; }
                    .harmless { background-color: #2196f3; }
                    .timeout { background-color: #9e9e9e; }
                    .tags { display: flex; flex-wrap: wrap; gap: 10px; }
                    .tag { padding: 6px 12px; background-color: #0073e6; color: white; border-radius: 20px; font-size: 14px; }
                    pre { background-color: #f1f1f1; padding: 10px; border-radius: 5px; overflow-x: auto; }
                    footer { text-align: center; padding: 20px 0; font-size: 14px; color: #777; }
                    th, td:first-child { width: 30%; }
                    td { width: 70%; }
                    .clean { background-color: #4caf50; } /* Green for CLEAN */
                    .malicious { background-color: #f44336; } /* Red for malicious */
                </style></head><body>";

            echo "<div class='container'>";
            echo "<div class='header'><img src='https://www.virustotal.com/favicon.ico' alt='VirusTotal Logo'><h1>Analyse de l'URL : {$url}</h1></div>";

            echo "<h2>Détails de l'URL</h2>";
            echo "<table><tr><th>ID de l'URL</th><td>" . $data['data'][0]['id'] . "</td></tr>";
            echo "<tr><th>Type</th><td>" . $data['data'][0]['type'] . "</td></tr>";
            echo "<tr><th>Date de l'analyse</th><td>" . date("d-m-Y H:i:s", $data['data'][0]['attributes']['date']) . "</td></tr>";
            echo "<tr><th>Votes positifs</th><td>" . $data['data'][0]['attributes']['votes']['positive'] . "</td></tr>";
            echo "<tr><th>Votes négatifs</th><td>" . $data['data'][0]['attributes']['votes']['negative'] . "</td></tr></table>";


            echo "<h2>Commentaires</h2>";
            echo "<table>";

            foreach ($data['data'] as $comment) {
                $commentVerdict = isset($comment['attributes']['last_analysis_stats']['malicious']) && $comment['attributes']['last_analysis_stats']['malicious'] > 0 ? 'malicious' : 'clean';

                $commentClass = ($commentVerdict === 'clean') ? 'clean' : 'malicious';

                echo "<tr><th>Texte du commentaire</th><td class='{$commentClass}'><pre>" . $comment['attributes']['text'] . "</pre></td></tr>";
                echo "<tr><th>Date du commentaire</th><td>" . date("d-m-Y H:i:s", $comment['attributes']['date']) . "</td></tr>";
                echo "<tr><th>Votes positifs</th><td>" . $comment['attributes']['votes']['positive'] . "</td></tr>";
                echo "<tr><th>Votes négatifs</th><td>" . $comment['attributes']['votes']['negative'] . "</td></tr>";
            }

            echo "</table>";
            echo "</div>";
            echo "<footer>&copy; 2025 Analyse URL VirusTotal</footer>";
            echo "</body></html>";
        } else {
            echo "Aucune information disponible pour cette URL.";
        }
    }

    public function showDashboard()
    {
        $decodedFile = './src/Logs/decoded_logs.txt';

        if (!file_exists($decodedFile)) {
            echo "Le fichier décodé n'existe pas. Veuillez d'abord exécuter la méthode decodeFile.\n";
            return;
        }

        $data = $this->initializeData();

        $file = fopen($decodedFile, 'r');
        if (!$file) {
            echo "Erreur lors de l'ouverture du fichier.\n";
            return;
        }

        while (($line = fgets($file)) !== false) {
            $this->processLine($line, $data);
        }

        fclose($file);

        $mac = $this->test();
        $scan = $this->scan();
        $scanURI = $this->scanURI();
        $scanHttp = $this->scanHttp();
        $scanDl = $this->scanDl();
        $scanDLURL = $this->scanDLURL();
        $analyzeRdpTraffic = $this->analyzeRdpTraffic();

        $jsonData = json_encode([
            'ethernet_frames' => $data['ethernet_frames'],
            'ipv4_frames' => $data['ipv4_frames'],
            'udp_frames' => $data['udp_frames'],
            'tcp_frames' => $data['tcp_frames'],
            'kerberos_frames' => $data['kerberos_frames'],
            'nbns_queries' => $data['nbns_queries'],
            'ssdp_frames' => $data['ssdp_frames'],
            'broadcast_addresses' => $data['broadcast_addresses'],
            'src_addresses' => $data['src_addresses'],
            'dst_addresses' => $data['dst_addresses'],
            'ethernet_sources' => $data['ethernet_sources'],
            'ethernet_dests' => $data['ethernet_dests'],
            'tcp_ports' => $data['tcp_ports'],
            'kerberos_services' => $data['kerberos_services'],
            'kerberos_realms' => $data['kerberos_realms'],
            'url' => $data['url'],
            'logs_length' => $data['logs_length'],
            'dst_ports' => $data['dst_ports'],
            'mac' => $mac,
            'scan' => $scan,
            'scanURI' => $scanURI,
            'scanHttp' => $scanHttp,
            'scanDl' => $scanDl,
            'scanDLURL' => $scanDLURL,
            'analyzeRdpTraffic' => $analyzeRdpTraffic,
        ]);
        echo $jsonData;
    }

    public function test()
    {
        $pcapFile = 'src/Logs/logs';
        $output = shell_exec("tshark -r $pcapFile -T fields \
        -e frame.time -e eth.src -e ip.src -e nbns.name \
        -e ip.dst -e eth.dst -e http.host -e http.request.uri -e dns.qry.name");

        $lines = explode("\n", trim($output));

        $tableData = [];

        foreach ($lines as $line) {
            $fields = explode("\t", $line);

            $dnsQueryName = isset($fields[8]) ? $fields[8] : '';
            $nbnsName = isset($fields[3]) ? $fields[3] : '';

            if (empty($dnsQueryName) && empty($nbnsName)) {
                continue;
            }

            if (count($fields) == 9) {
                $tableData[] = [
                    'time' => $fields[0],
                    'src_mac' => $fields[1],
                    'src_ip' => $fields[2],
                    'nbns_name' => $fields[3],
                    'dst_ip' => $fields[4],
                    'dst_mac' => $fields[5],
                    'dns_query_name' => $fields[8]
                ];
            }
        }

        return $tableData;
    }

    public function filterMachineDnsQueries($data)
    {
        $regex = '/^[A-Z0-9]+-[A-Z0-9]+/';
        $seen = [];
        $result = [];

        foreach ($data as $item) {
            $dnsQueryNamePart = explode('.', $item['dns_query_name'])[0];

            if (preg_match($regex, $dnsQueryNamePart)) {
                $key = $dnsQueryNamePart . '-' . $item['dst_mac'] . '-' . $item['dst_ip'];

                if (!in_array($key, $seen)) {
                    $seen[] = $key;

                    $result[] = [
                        'lines' => [
                            $item['dst_mac'],
                            $item['dst_ip'],
                            $dnsQueryNamePart
                        ]
                    ];
                }
            }
        }

        return $result;
    }
    public function flag()
    {
        $user_id = "Xavier Pelle";

        $testData = $this->test();
        $filteredData = $this->filterMachineDnsQueries($testData);
        $karberos_names = $this->processKerberosCName();

        $result = [];
        foreach ($karberos_names as $kerberos_name) {
            foreach ($filteredData as $item) {
                $item['lines'][] = $kerberos_name;

                $result[] = [
                    'user_id' => $user_id,
                    'lines' => $item['lines']
                ];
            }
        }
        $this->sendToApi($result);
    }

    private function sendToApi($result)
    {
        $url = 'http://93.127.203.48:5000/pcap/submit';
        foreach ($result as $data) {
            $jsonData = json_encode($data);

            $ch = curl_init($url);

            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonData);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($jsonData)
            ]);

            $response = curl_exec($ch);

            if (curl_errno($ch)) {
                echo 'Error:' . curl_error($ch);
            }

            curl_close($ch);

            $responseData = json_decode($response, true);

            if (isset($responseData['flag'])) {
                $result = json_encode([
                    'flag' => $responseData['flag'],
                    'data' => $jsonData,
                ]);
                echo $result;
            }
        }
    }

    function processKerberosCName()
    {
        $decodedFile = './src/Logs/decoded_logs.txt';

        $data = [];
        if ($file = fopen($decodedFile, 'r')) {
            while (($line = fgets($file)) !== false) {
                if (preg_match('/CNameString:\s*([^,]+)/', $line, $matches)) {
                    $cname = trim($matches[1]);

                    if (preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$/', $cname)) {
                        $data[] = $cname;
                    } else if (preg_match('/^[a-zA-Z0-9.-]+$/', $cname)) {
                        $data[] = $cname;
                    }
                }
            }
            fclose($file);
        } else {
            echo "Erreur lors de l'ouverture du fichier.";
        }

        $counts = array_count_values($data);

        $filteredData = [];
        foreach ($counts as $cname => $count) {
            if ($count > 1) {
                $filteredData[] = $cname;
            }
        }

        return $filteredData;
    }
    public function scan()
    {
        $pcapFile = 'src/Logs/logs';
        $output = shell_exec("tshark -r $pcapFile -Y 'tcp.flags.syn == 1 and tcp.flags.ack == 0' -T fields -e ip.src -e tcp.dstport | sort | uniq -c");

        $data = [];

        $lines = explode("\n", $output);

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }

            $parts = preg_split('/\s+/', $line);

            if (count($parts) >= 3) {
                $count = $parts[0];
                $ip = $parts[1];
                $port = $parts[2];

                $data[] = [
                    'count' => $count,
                    'ip' => $ip,
                    'port' => $port,
                ];
            }
        }
        return $data;
    }

    public function scanURI() {
        $pcapFile = 'src/Logs/logs';
        $output = shell_exec("tshark -r $pcapFile -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri");
    
        $data = [];
    
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }
    
            $parts = preg_split('/\s+/', $line);
            
            if (count($parts) >= 3) {
                $ip = $parts[0];      
                $host = $parts[1]; 
                $uri = $parts[2];     
    
                $data[] = [
                    'ip' => $ip,
                    'host' => $host,
                    'uri' => $uri,
                ];
            }
        }

    
        return $data; 
    }
    public function scanHttp() {
        $pcapFile = 'src/Logs/logs';  
        $output = shell_exec("tshark -r $pcapFile -Y 'ftp' -T fields -e ip.src -e ftp.request.command -e ftp.request.arg");
    
        $data = [];
    
        $lines = explode("\n", $output);
    
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }
    
            $parts = preg_split('/\s+/', $line);
    
            if (count($parts) >= 3) {
                $ip = $parts[0];         
                $command = $parts[1];    
                $arg = isset($parts[2]) ? $parts[2] : '';
    
                $data[] = [
                    'ip' => $ip,
                    'command' => $command,
                    'arg' => $arg,
                ];
            }
        }
    
        return $data; 
    }

    public function scanDl() {
        $pcapFile = 'src/Logs/logs';  
        $output = shell_exec("tshark -r $pcapFile -Y 'http.response.code == 200' -T fields -e ip.src -e ip.dst -e http.response.code");
    
        $data = [];
   
        $lines = explode("\n", $output);
    
        foreach ($lines as $line) {
        
            $line = trim($line);
            if (empty($line)) {
                continue;
            }
    
        
            $parts = preg_split('/\s+/', $line);
    
            if (count($parts) >= 3) {

                $srcIp = $parts[0];       
                $dstIp = $parts[1];   
                $httpCode = $parts[2];   

                $data[] = [
                    'src_ip' => $srcIp,
                    'dst_ip' => $dstIp,
                    'http_code' => $httpCode,
                ];
            }
        }
    
        return $data;
    }
    public function scanDLURL() {
        $pcapFile = 'src/Logs/logs';
        $output = shell_exec("tshark -r $pcapFile -Y 'http.response.code == 200' -T fields -e ip.src -e http.host -e http.request.uri -e http.content_type -e http.content_length");
    
        $data = [];
        $lines = explode("\n", $output);
    
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }
    
            $parts = preg_split('/\s+/', $line);
    
            if (count($parts) >= 5) {
                $data[] = [
                    'ip' => $parts[0],
                    'host' => $parts[1],
                    'uri' => $parts[2],
                    'content_type' => $parts[3],
                    'content_length' => $parts[4],
                ];
            }
        }
    
        return $data;
    }
    public function analyzeRdpTraffic() {
        $pcapFile = 'src/Logs/logs';
        $output = shell_exec("tshark -r $pcapFile -Y 'tcp.port == 3389' -T fields -e frame.time -e ip.src -e ip.dst");
    
        $data = [];
        $lines = explode("\n", $output);
    
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }
    
            $parts = preg_split('/\s+/', $line);
    
            if (count($parts) >= 3) {
                $data[] = [
                    'time' => $parts[0],
                    'src_ip' => $parts[1],
                    'dst_ip' => $parts[2],
                ];
            }
        }
    
        return $data;
    }
    
}
