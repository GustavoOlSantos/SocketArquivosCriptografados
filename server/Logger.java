package server;

import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Logger {

    private static final String LOG_PATH = "log/server.log";

    public static void log(String message) {
        try {
            Path path = Paths.get(LOG_PATH);

            // cria pasta e arquivo se não existir
            if (!Files.exists(path)) {
                Files.createDirectories(path.getParent());
                Files.createFile(path);
            }

            FileWriter fw = new FileWriter(path.toFile(), true);
            BufferedWriter bw = new BufferedWriter(fw);

            String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

            bw.write("[" + timestamp + "] " + message);
            bw.newLine();

            bw.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void logBytes(String label, byte[] data) {
        StringBuilder sb = new StringBuilder();

        for (byte b : data) {
            sb.append(String.format("%02X ", b));
        }

        log(label + " (HEX): " + sb.toString());
    }
}