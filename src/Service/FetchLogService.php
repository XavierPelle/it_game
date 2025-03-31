<?php

class FetchLogService
{
    public function fetchLogFile()
    {
        $url = 'http://93.127.203.48:5000/pcap/latest';
        $destinationFolder = './src/Logs';

        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            echo "URL invalide.";
            return false;
        }

        $fileName = 'logs'; 
        $destinationPath = rtrim($destinationFolder, '/') . '/' . $fileName;

        $fileContent = file_get_contents($url);

        if ($fileContent === false) {
            echo "Échec du téléchargement du fichier.";
            return false;
        }

        $fileSaved = file_put_contents($destinationPath, $fileContent);

        if ($fileSaved === false) {
            echo "Impossible de sauvegarder le fichier.";
            return false;
        }

        echo "Fichier téléchargé avec succès : " . $destinationPath;
        return true;
    }
}
