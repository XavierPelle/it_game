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
                $url = $matches[0];
                if (strpos(strtolower($url), 'microsoft') === false && strpos(strtolower($url), 'windowsupdate') === false) {
                    $data['url'][$url] = ($data['url'][$url] ?? 0) + 1;
                }
            }
        }

        $data['logs_length']++;
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
    
                        /* Nouveau style pour les colonnes */
                        th, td:first-child {
                            width: 30%; /* Colonne de gauche (ID, Type, etc.) */
                        }
    
                        td {
                            width: 70%; /* Colonne de droite (valeurs) */
                        }
                    </style></head><body>";

                echo "<div class='container'>";
                echo "<div class='header'><img src='https://www.virustotal.com/favicon.ico' alt='VirusTotal Logo'><h1>Analyse de l'IP : {$ip}</h1></div>";

                echo "<h2>Détails de l'IP</h2>";
                echo "<table><tr><th>ID de l'IP</th><td>" . $data['data']['id'] . "</td></tr>";
                echo "<tr><th>Type</th><td>" . $data['data']['type'] . "</td></tr>";
                echo "<tr><th>Tags</th><td><div class='tags'>";
                foreach ($data['data']['attributes']['tags'] as $tag) {
                    echo "<span class='tag'>{$tag}</span>";
                }
                echo "</div></td></tr>";
                echo "<tr><th>Whois</th><td><pre>" . $data['data']['attributes']['whois'] . "</pre></td></tr></table>";

                echo "<h2>Statistiques d'analyse</h2>";
                $stats = $data['data']['attributes']['last_analysis_stats'];
                echo "<table><tr><th>Malicious</th><td class='malicious'>" . $stats['malicious'] . "</td></tr>";
                echo "<tr><th>Suspicious</th><td class='suspicious'>" . $stats['suspicious'] . "</td></tr>";
                echo "<tr><th>Undetected</th><td class='undetected'>" . $stats['undetected'] . "</td></tr>";
                echo "<tr><th>Harmless</th><td class='harmless'>" . $stats['harmless'] . "</td></tr>";
                echo "<tr><th>Timeout</th><td class='timeout'>" . $stats['timeout'] . "</td></tr></table>";

                echo "<h2>Résultats de l'analyse par moteur</h2>";
                echo "<table><tr><th>Moteur</th><th>Résultat</th><th>Catégorie</th><th>État</th></tr>";
                foreach ($data['data']['attributes']['last_analysis_results'] as $engine => $result) {
                    echo "<tr><td>{$engine}</td><td>{$result['result']}</td><td>{$result['category']}</td><td>{$result['method']}</td></tr>";
                }
                echo "</table>";
                echo "</div>";

                echo "<footer>&copy; 2025 Analyse IP VirusTotal</footer>";
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
        ]);
        echo $jsonData;
    }

    private function getIpCoordinates($ipAddresses)
    {
        $coordinates = [];
        $apiUrl = 'http://ip-api.com/json/';

        foreach ($ipAddresses as $ip) {
            $response = file_get_contents($apiUrl . $ip);
            $data = json_decode($response, true);

            if ($data && $data['status'] === 'success') {
                $coordinates[] = [
                    'ip' => $ip,
                    'latitude' => $data['lat'],
                    'longitude' => $data['lon']
                ];
            } else {
                $coordinates[] = [
                    'ip' => $ip,
                    'latitude' => null,
                    'longitude' => null
                ];
            }
        }
        return $coordinates;
    }

    public function test()
    {
        $pcapFile = 'src/Logs/logs';

        $output = shell_exec("tshark -r $pcapFile -Y 'dns.qry.name' -T fields -e eth.src -e dns.qry.name -e kerberos.CNameString -e dhcp.option.hostname");


        var_dump($output);
    }
}
