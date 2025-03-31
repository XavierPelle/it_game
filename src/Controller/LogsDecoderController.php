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
        ];
    }

    private function processLine($line, &$data)
    {
        if (strpos($line, "Ethernet II") !== false) {
            $data['ethernet_frames']++;
            if (preg_match('/Src: ([^\s]+)/', $line, $matches)) {
                $source = trim($matches[1]);
                $data['ethernet_sources'][$source] = ($data['ethernet_sources'][$source] ?? 0) + 1;
            }
            if (preg_match('/Dst: ([^\s]+)/', $line, $matches)) {
                $destination = trim($matches[1]);
                $data['ethernet_dests'][$destination] = ($data['ethernet_dests'][$destination] ?? 0) + 1;
            }
        }

        if (strpos($line, "Internet Protocol Version 4") !== false) {
            $data['ipv4_frames']++;
            if (preg_match('/Src: ([^\s]+)/', $line, $matches)) {
                $source = trim($matches[1]);
                $data['src_addresses'][$source] = ($data['src_addresses'][$source] ?? 0) + 1;
            }
            if (preg_match('/Dst: ([^\s]+)/', $line, $matches)) {
                $destination = trim($matches[1]);
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

        if (strpos($line, "nbns") !== false) {
            $data['nbns_queries']++;
            if (strpos($line, "Broadcast") !== false) {
                $data['broadcast_addresses']++;
            }
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
        echo "<h1>Résumé de l'analyse des logs</h1>";
    
        echo "<table><tr><th>Type</th><th>Nombre</th></tr>";
        echo "<tr><td>Trames Ethernet</td><td>{$data['ethernet_frames']}</td></tr>";
        echo "<tr><td>Trames IPv4</td><td>{$data['ipv4_frames']}</td></tr>";
        echo "<tr><td>Trames UDP</td><td>{$data['udp_frames']}</td></tr>";
        echo "<tr><td>Trames TCP</td><td>{$data['tcp_frames']}</td></tr>";
        echo "<tr><td>Trames Kerberos</td><td>{$data['kerberos_frames']}</td></tr>";
        echo "<tr><td>Requêtes NBNS</td><td>{$data['nbns_queries']}</td></tr>";
        echo "<tr><td>Adresses Broadcast</td><td>{$data['broadcast_addresses']}</td></tr>";
        echo "</table>";
    
        $this->generateAddressTable("Adresses source", $data['src_addresses']);
        $this->generateAddressTable("Adresses destination", $data['dst_addresses']);
        $this->generateAddressTable("Adresses Ethernet source", $data['ethernet_sources']);
        $this->generateAddressTable("Adresses Ethernet destination", $data['ethernet_dests']);
    
        $this->generateTable("Ports TCP", $data['tcp_ports']);
        $this->generateTable("Services Kerberos", $data['kerberos_services']);
        $this->generateTable("Régions Kerberos", $data['kerberos_realms']);
    
        echo "</div>";
    
        echo "</body></html>";
    }
    
    private function generateAddressTable($title, $data)
    {
        echo "<h2>$title</h2>";
        echo "<table><tr><th>Adresse</th><th>Occurrences</th></tr>";
        foreach ($data as $address => $count) {
            echo "<tr><td><a href='/analyzeIP?ip=$address' target='_blank'>$address</a></td><td>$count</td></tr>";
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

    public function analyzeIpWithVirusTotal()
    {
        if (isset($_GET['ip'])) {
            $ip = $_GET['ip'];
        } else {
            echo "Aucune adresse IP fournie.";
            return;
        }
    
        $apiKey = '';
        $url = 'https://www.virustotal.com/api/v3/ip_addresses/' . urlencode($ip);
    
        $ch = curl_init();
    
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'x-apikey: ' . $apiKey
        ]);
    
        $response = curl_exec($ch);
    
        if(curl_errno($ch)) {
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
    
}

?>
