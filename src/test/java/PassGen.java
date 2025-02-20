import com.nathcat.RSA.EncryptedObject;
import com.nathcat.RSA.KeyPair;
import com.nathcat.RSA.PublicKeyException;
import com.nathcat.aggrocat_server.Server;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class PassGen {
    @Test
    public void test() throws IOException, PublicKeyException, InterruptedException {
        KeyPair p = Server.readKey(Server.PATH_KEY);
        EncryptedObject o = p.encrypt(Server.CIPHER_STRING);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.flush();

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest r = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/AddPoint?user=1"))
                .POST(HttpRequest.BodyPublishers.ofByteArray(baos.toByteArray()))
                .build();

        oos.close();
        baos.close();

        HttpResponse<String> response = client.send(r, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
    }
}
