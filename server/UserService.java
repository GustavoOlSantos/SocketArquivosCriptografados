package server;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class UserService {

    private static Map<String, String> users = new HashMap<>();

    static {
        try {
            List<String> lines = Files.readAllLines(Paths.get("server/user/users.txt"));

            for (String line : lines) {
                line = line.trim(); // 🔥 IMPORTANTE
                if (line.isEmpty()) continue;

                String[] parts = line.split(":");
                users.put(parts[0], parts[1]);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean login(String user, String password) throws Exception {
        String hash = CryptoUtils.hashSHA256(password).trim();

        return users.containsKey(user.trim()) &&
            users.get(user.trim()).equals(hash);
    }

    public static boolean register(String user, String password) throws Exception {
        String hash = CryptoUtils.hashSHA256(password);

        try {
            FileWriter fw = new FileWriter("server/user/users.txt", true);
            fw.write(user + ":" + hash + "\n");
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }
}