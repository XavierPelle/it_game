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

    
    public function uploadLogFile()
{
    $destinationFolder = './src/Logs';
    file_put_contents('./src/Logs/debug_upload.txt', print_r($_FILES, true));


    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'Fichier non reçu ou erreur de téléchargement.'
        ]);
        return;
    }

    $fileTmpPath = $_FILES['file']['tmp_name'];
    $destinationPath = $destinationFolder . '/logs';

    // Lecture brute comme dans fetchLogFile
    $fileContent = file_get_contents($fileTmpPath);
    if ($fileContent === false || strlen($fileContent) < 1000) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'message' => 'Le fichier est vide ou trop petit.'
        ]);
        return;
    }

    $result = file_put_contents($destinationPath, $fileContent);
    if ($result === false) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'Impossible de sauvegarder le fichier.'
        ]);
        return;
    }

    echo json_encode([
        'success' => true,
        'message' => "Fichier PCAP importé sur le serveur : $destinationPath"
    ]);
}


}
