<?php

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

    public function readDecodedFile()
    {
        $file = './src/Logs/decoded_logs.txt';

        if (file_exists($file) && is_readable($file)) {
            $content = file_get_contents($file);
            echo "<pre>$content</pre>";
        } else {
            echo "Le fichier n'existe pas ou n'est pas lisible.";
        }
    }

    public function analyzeLogs()
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

        if (isset($_GET['abuseCheck'])) {
            $ip = $_GET['abuseCheck'];
            $apiKey = '16ac9dfa2f6bec5ee41423b2ab52797178d1e576d7ab91be587f47adf4f9a45fbe761d9e470ceced';
            $comments = $this->getAbuseIpComments($ip, $apiKey);

            echo "<h2>Commentaires pour $ip</h2>";
            foreach ($comments as $c) {
                echo "📅 " . $c['date'] . "<br>";
                echo "💬 " . htmlspecialchars($this->simplifyComment($c['comment'])) . "<br>";
                echo "🌍 " . $c['reporterCountryCode'] . "<hr>";
            }
        }


        fclose($file);
        $this->generateHtmlTable($data);
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
            'src_addresses' => [],
            'dst_addresses' => [],
            'ethernet_sources' => [],
            'ethernet_dests' => [],
            'tcp_ports' => [],
            'kerberos_services' => [],
            'kerberos_realms' => [],
            'ssdp_frames'  => 0,
            'url' => [],
            'countries' => [],
            'cities' => [],
            'alerts' => [],
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
                $data['tcp_ports'][$port] = ($data['tcp_ports'][$port] ?? 0) + 1;
            }
        }

        if (preg_match('/CNameString:\s*([^,]+)/', $line, $matches)) {
            $cname = trim($matches[1]);
            $data['kerberos_services'][$cname] = ($data['kerberos_services'][$cname] ?? 0) + 1;
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
                $url = rtrim($matches[0], '*');
                $data['url'][$url] = ($data['url'][$url] ?? 0) + 1;
            }
        }
        if (preg_match('/CountryName:\s*([A-Z]{2})/', $line, $match)) {
            $countryCode = $match[1];
            $data['countries'][$countryCode] = ($data['countries'][$countryCode] ?? 0) + 1;
        }
        
        if (preg_match('/localityName\s*=\s*([^\s,]+)/', $line, $match)) {
            $city = rtrim($match[1],')');
            $data['cities'][$city] = ($data['cities'][$city] ?? 0) + 1;
        }
    }

    public function generateHtmlTable($data)
    {
        echo "<!DOCTYPE html><html lang='fr'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>Analyse des Logs</title><style>
                    body { font-family: Arial, sans-serif; padding: 20px; background-color: #f9f9f9; }
                    h1 { color: #333; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th, td { padding: 12px; text-align: left; border: 1px solid #ddd; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                    tr:hover { background-color: #f1f1f1; }
                    .container { max-width: 800px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); border-radius: 8px; }
                    .whois { max-height: 300px; overflow-y: scroll; white-space: pre-wrap; word-wrap: break-word; background-color: #f4f4f4; padding: 10px; }
                    a { color: #1a73e8; text-decoration: none; }
                    a:hover { text-decoration: underline; }
                </style></head><body>";

        echo "<div class='container'>";
        echo "<script>
        function toggleDetail(id) {
        const row = document.getElementById(id);
        if (row.style.display === 'none' || row.style.display === '') {
            row.style.display = 'table-row';
        } else {
            row.style.display = 'none';
        }
        }
        </script>";
        

        echo "<h1>Résumé de l'analyse des logs</h1>";

        echo "<table><tr><th>Type</th><th>Nombre</th></tr>";
        echo "<tr><td>Trames Ethernet</td><td>{$data['ethernet_frames']}</td></tr>";
        echo "<tr><td>Trames IPv4</td><td>{$data['ipv4_frames']}</td></tr>";
        echo "<tr><td>Trames UDP</td><td>{$data['udp_frames']}</td></tr>";
        echo "<tr><td>Trames TCP</td><td>{$data['tcp_frames']}</td></tr>";
        echo "<tr><td>Trames Kerberos</td><td>{$data['kerberos_frames']}</td></tr>";
        echo "<tr><td>Requêtes NBNS</td><td>{$data['nbns_queries']}</td></tr>";
        echo "<tr><td>Requêtes SSDP</td><td>{$data['ssdp_frames']}</td></tr>";
        echo "<tr><td>Adresses Broadcast</td><td>{$data['broadcast_addresses']}</td></tr>";
        echo "</table>";

        $this->generateAddressTable("Adresses source", $data['src_addresses']);
        $this->generateAddressTable("Adresses destination", $data['dst_addresses']);
        $this->generateTable("Adresses Ethernet source", $data['ethernet_sources']);
        $this->generateTable("Adresses Ethernet destination", $data['ethernet_dests']);

        $this->generateTable("Ports TCP", $data['tcp_ports']);
        $this->generateTable("Services Kerberos", $data['kerberos_services']);
        $this->generateTable("Régions Kerberos", $data['kerberos_realms']);
        $this->generateUrlTable("URL", $data['url']);
        if (!empty($data['countries'])) {
            echo "<h2>Pays présents dans les certificats / logs</h2>";
            echo "<table><tr><th>Pays</th><th>Occurrences</th></tr>";
            foreach ($data['countries'] as $code => $count) {
                echo "<tr><td>$code</td><td>$count</td></tr>";
            }
            echo "</table>";
        }
        
        if (!empty($data['cities'])) {
            echo "<h2>Villes détectées</h2>";
            echo "<table><tr><th>Ville</th><th>Occurrences</th></tr>";
            foreach ($data['cities'] as $city => $count) {
                echo "<tr><td>$city</td><td>$count</td></tr>";
            }
            echo "</table>";
        }

        $apiKey = '16ac9dfa2f6bec5ee41423b2ab52797178d1e576d7ab91be587f47adf4f9a45fbe761d9e470ceced';
        $ip = '52.113.196.254';

        $comments =$this->getAbuseIpComments($ip, $apiKey);

        if (!empty($comments)) {
            echo "<h2>Commentaires AbuseIPDB filtrés</h2>";
            echo "<table><tr><th>Date</th><th>Pays</th><th>Résumé</th></tr>";
        
            foreach ($comments as $c) {
                $date = htmlspecialchars($c['date']);
                $country = htmlspecialchars($c['reporterCountryCode']);
                $summary = $this->simplifyComment($c['comment']);
        
                echo "<tr><td>$date</td><td>$country</td><td>$summary</td></tr>";
            }
        
            echo "</table>";
        } else {
            echo "<p>Aucun commentaire trouvé pour l'IP $ip.</p>";
        }
        
        echo "<script>
        function toggleDetail(id) {
            const el = document.getElementById(id);
            el.style.display = (el.style.display === 'none' || el.style.display === '') ? 'block' : 'none';
        }
        </script>";


        echo "</div>";
        echo "</body></html>";
    }

    private function generateAddressTable($title, $data)
    {
        echo "<h2>$title</h2>";
        echo "<table><tr><th>Adresse</th><th>Occurrences</th><th>Actions</th></tr>";
    
        foreach ($data as $address => $count) {
            $id = 'actions_' . md5($address);
    
            echo "<tr>";
            echo "<td>
                    <span style='cursor:pointer;' onclick=\"toggleDetail('$id')\">🔽</span>
                    <span style='margin-left: 8px;'><a href='/analyzeIP?ip=$address' target='_blank'>$address</a></span>
                  </td>";
            echo "<td>$count</td>";
            echo "<td>
                    <div id='$id' style='display: none; margin-top: 8px;'>
                        <a href='/analyzeIP?ip=$address' target='_blank'>
                            <button style='margin-right:10px;'>VirusTotal</button>
                        </a>
                        <a href='?abuseCheck=$address'>
                            <button>AbuseIPDB</button>
                        </a>
                    </div>
                  </td>";
            echo "</tr>";
        }
    
        echo "</table>";
    }
    

    private function generateUrlTable($title, $data)
    {
        echo "<h2>$title</h2>";
        echo "<table><tr><th>Url</th><th>Occurrences</th></tr>";
        foreach ($data as $url => $count) {
            echo "<tr><td><a href='/analyzeURL?urls=$url' target='_blank'>$url</a></td><td>$count</td></tr>";
        }
        echo "</table>";
    }

    private function generateTable($title, $data)
    {
        echo "<h2>$title</h2>";
        echo "<table><tr><th>Élément</th><th>Occurrences</th></tr>";
        foreach ($data as $key => $count) {
            echo "<tr><td>$key</td><td>$count</td></tr>";
        }
        echo "</table>";
    }

    function getAbuseIpComments($ip, $apiKey) {
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
    
        $comments = [];
    
        if (isset($data['data']['reports'])) {
            foreach ($data['data']['reports'] as $report) {
                $comments[] = [
                    'date' => $report['reportedAt'],
                    'comment' => $report['comment'],
                    'categories' => $report['categories'], // tu peux aussi utiliser ça
                    'reporterCountryCode' => $report['reporterCountryCode']
                ];
            }
        }
    
        return $comments;
    }

    public function analyzeIpWithVirusTotal()
    {
        if (isset($_GET['ip'])) {
            $ip = $_GET['ip'];
        } else {
            echo "Aucune adresse IP fournie.";
            return;
        }

        $apiKey = '168a3d3874c712ae9d6fc313ae20f0fbc44cbf6bc9f98a818302a05e5056163c';
        $url = 'https://www.virustotal.com/api/v3/ip_addresses/' . urlencode($ip);

        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'x-apikey: ' . $apiKey
        ]);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            echo 'Erreur cURL : ' . curl_error($ch);
        }

        curl_close($ch);

        if ($response) {
            $data = json_decode($response, true);

            if (isset($data['data'])) {
                echo "<!DOCTYPE html><html lang='fr'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>Analyse de l'IP</title><style>
                        body { font-family: Arial, sans-serif; padding: 20px; background-color: #f9f9f9; }
                        h1 { color: #333; }
                        table { width: 100%; border-collapse: collapse; margin-top: 20px; text-wrap: wrap;}
                        th, td { padding: 12px; text-align: left; border: 1px solid #ddd; text-wrap: wrap; }
                        th { background-color: #f2f2f2; text-wrap: wrap;}
                        tr:nth-child(even) { background-color: #f9f9f9; }
                        tr:hover { background-color: #f1f1f1; }
                        .container { max-width: 800px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); border-radius: 8px; }
                    </style></head><body>";

                echo "<div class='container'>";
                echo "<h1>Analyse de l'IP : {$ip}</h1>";

                echo "<h2>Détails de l'IP</h2>";
                echo "<table><tr><th>ID de l'IP</th><td>" . $data['data']['id'] . "</td></tr>";
                echo "<tr><th>Type</th><td>" . $data['data']['type'] . "</td></tr>";
                echo "<tr><th>Tags</th><td>" . implode(", ", $data['data']['attributes']['tags']) . "</td></tr>";
                echo "<tr><th>Whois</th><td><pre>" . $data['data']['attributes']['whois'] . "</pre></td></tr></table>";

                echo "<h2>Statistiques d'analyse</h2>";
                $stats = $data['data']['attributes']['last_analysis_stats'];
                echo "<table><tr><th>Malicious</th><td>" . $stats['malicious'] . "</td></tr>";
                echo "<tr><th>Suspicious</th><td>" . $stats['suspicious'] . "</td></tr>";
                echo "<tr><th>Undetected</th><td>" . $stats['undetected'] . "</td></tr>";
                echo "<tr><th>Harmless</th><td>" . $stats['harmless'] . "</td></tr>";
                echo "<tr><th>Timeout</th><td>" . $stats['timeout'] . "</td></tr></table>";

                echo "<h2>Résultats de l'analyse par moteur</h2>";
                echo "<table><tr><th>Moteur</th><th>Résultat</th><th>Catégorie</th><th>État</th></tr>";
                foreach ($data['data']['attributes']['last_analysis_results'] as $engine => $result) {
                    echo "<tr><td>{$engine}</td><td>{$result['result']}</td><td>{$result['category']}</td><td>{$result['method']}</td></tr>";
                }
                echo "</table>";
                echo "</div>";

                echo "</body></html>";
            } else {
                echo "Aucune information disponible pour cette adresse IP.";
            }
        } else {
            echo "Erreur lors de l'analyse de l'IP avec l'API VirusTotal.";
        }
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

        print_r($data);
    }
    public function testAbuse()
{
    $ip = '239.255.255.250'; // IP connue comme malveillante

    $result = $this->queryAbuseIpDb($ip);

    echo "<pre>";
    echo "Résultat de la requête pour $ip :\n";
    var_dump($result);
    echo "</pre>";
}

    private function queryAbuseIpDb($ip)
{
    $apiKey = '16ac9dfa2f6bec5ee41423b2ab52797178d1e576d7ab91be587f47adf4f9a45fbe761d9e470ceced';
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress={$ip}&maxAgeInDays=90";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Key: $apiKey",
        "Accept: application/json"
    ]);
    $response = curl_exec($ch);
    curl_close($ch);

    if (!$response) return null;

    $data = json_decode($response, true);
    return $data['data'] ?? null;
}


private function simplifyComment($comment)
{
    $patterns = [
        '/brute force/i' => 'Brute force',
        '/spam/i' => 'Spam',
        '/sql injection/i' => 'SQL Injection',
        '/scanner|scan/i' => 'Scan détecté',
        '/crawler impostor/i' => 'Faux bot Google',
        '/fail2ban/i' => 'Bloqué par Fail2Ban',
        '/xmlrpc/i' => 'Attaque XML-RPC',
        '/mod_security/i' => 'Déclenché par ModSecurity',
        '/cloudflare/i' => 'Déclenché par WAF Cloudflare',
        '/wordpress/i' => 'Scan WordPress',
        '/ddos/i' => 'Tentative de DDoS',
        '/registration hack/i' => 'Tentative d’inscription pirate',
        '/honeypot/i' => 'Détection Honeypot',
        '/web form/i' => 'Spam via formulaire',
        '/rdp/i' => 'Tentative brute RDP',
        '/phishing/i' => 'Phishing détecté',
        '/port scanning/i' => 'Scan de ports suspect',
        '/api|trigger|custom/i' => 'Règle personnalisée/trigger',
    ];

    $summary = [];

    foreach ($patterns as $regex => $label) {
        if (preg_match($regex, $comment)) {
            $summary[] = $label;
        }
    }

    if (empty($summary)) {
        // Si aucun match, on affiche un bout du commentaire
        return substr(strip_tags($comment), 0, 80) . '...';
    }

    return implode(', ', array_unique($summary));
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
    
        echo json_encode([
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
            'countries' => $data['countries'],
            'cities' => $data['cities'],
        ]);
    }

    

}
