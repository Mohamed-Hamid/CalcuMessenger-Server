package com.bitsplease.calcumessenger_server;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import com.bitsplease.encryption.EncryptionUtil;
import com.bitsplease.utilities.Message;
import com.bitsplease.utilities.MessageBundle;
import com.bitsplease.utilities.MessageListingAdapter;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OptionalDataException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;


public class MainActivity extends Activity {

    private MessageListingAdapter adapter;
    private List<Message> listMessages;
    private ListView listViewMessages;

   // TextView messages;
    EditText enterMessage;
    Button sendMessage;

    private String senderName, receiverName;
    private ObjectOutputStream output;
    private ObjectInputStream input;
    private String chatServerIP = "192.168.43.1";
    private int chatServerPort = 12344;
    private ServerSocket server;
    private Socket connection;
    private PublicKey senderPublicKey;
    SecretKey secretKey;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //messages = (TextView) findViewById(R.id.messages);
        enterMessage = (EditText) findViewById(R.id.message);
        sendMessage = (Button) findViewById(R.id.send_button);
        listViewMessages = (ListView) findViewById(R.id.list_view_messages);

        receiverName = "You";

        listMessages = new ArrayList<Message>();

        adapter = new MessageListingAdapter(this, listMessages);
        listViewMessages.setAdapter(adapter);

        /*
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
                startActivity(new Intent("android.credentials.UNLOCK"));
                Log.w("YES", "UNLOCKED!");
            } else {
                startActivity(new Intent("com.android.credentials.UNLOCK"));
                Log.w("YES", "UNLOCKED!");
            }
        } catch (ActivityNotFoundException e) {
            Log.e("YES", "No UNLOCK activity: " + e.getMessage(), e);
        }
        */

        //KEY GENERATION
        try{
            if (!EncryptionUtil.areKeysPresent()) {
                EncryptionUtil.generateKey(this);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        String test = "Hello world!";
        /*
        try {
            String ans = EncryptionUtil.signData(test);
            boolean right = EncryptionUtil.verifyData(test, ans);
            Log.w("YES", "*_*"+right);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        */

        Thread cThread = new Thread(new ServerThread());
        cThread.start();

        sendMessage.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (enterMessage.getText().toString() != ""){
                    sendData( enterMessage.getText().toString() );
                    displayMessage( new Message(enterMessage.getText().toString(), receiverName, true) );
                    enterMessage.setText("");
                }
            }
        });

    }

    public class ServerThread implements Runnable {
        public void run() {
            try
            {
                server = new ServerSocket( chatServerPort, 100 );
                waitForConnection();
                getStreams();
                senderPublicKey =  handshake();
                processConnection();
            }
            catch ( EOFException e )
            {
               showToast( "Client terminated connection" );
                Log.w("YES", "*" + e.toString());
            }
            catch ( IOException e )
            {
                e.printStackTrace();
                Log.w("YES", "*" + e.toString());
            }
            catch (Exception e){
                Log.w("YES", "*" + e.toString());
            }
            finally
            {
                //closeConnection();
            }
        }
    }

    private PublicKey handshake() {
        //SEND MY PUBLIC KEY
        try {
            PublicKey pk = EncryptionUtil.getPublicKey();

            byte[] pKbytes = Base64.encode(pk.getEncoded(), 0);
            String pK = new String(pKbytes);
            String pubKey = "-----BEGIN PUBLIC KEY-----\n" + pK + "-----END PUBLIC KEY-----";

            Log.w("YES", "MY PUBLIC KEY = "+ pubKey);

            output.writeObject(pubKey);
            output.flush();
        } catch (Exception e) {
            Log.w("YES", e.getMessage());
        }

        //WAIT FOR HIS PUBLIC KEY
        try {
            String senderPublicKeyString = ((String) input.readObject());
            if (senderPublicKeyString.startsWith("-----BEGIN PUBLIC KEY-----")) {
                // Remove the first and last lines
                senderPublicKeyString = senderPublicKeyString.replace("-----BEGIN PUBLIC KEY-----\n", "");
                senderPublicKeyString = senderPublicKeyString.replace("-----END PUBLIC KEY-----", "");

                byte[] keyBytes = Base64.decode(senderPublicKeyString.getBytes("utf-8"), 0);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey key = keyFactory.generatePublic(spec);

                byte[] pKbytes = Base64.encode(key.getEncoded(), 0);
                String pK = new String(pKbytes);
                String pubKey = "-----BEGIN PUBLIC KEY-----\n" + pK + "-----END PUBLIC KEY-----";

                Log.w("YES", "HIS PUBLIC KEY = " + pubKey);

                if (key != null) {
                    secretKey = EncryptionUtil.generateAES();
                    byte[] secretKeyBytes = Base64.encode(secretKey.getEncoded(), 0);
                    String secretKeyString = new String(secretKeyBytes);
                    secretKeyString = "-----BEGIN AES KEY-----\n" + secretKeyString + "-----END AES KEY-----";

                    Log.w("YES", "THE SENT AES SECRET KEY = "+ secretKeyString);

                    //encryt symmetric key with his public key
                    String keyEncryptedWithPublicKey = EncryptionUtil.encryptDataPublicKey(secretKeyString, key);

                    //Log.w("YES", "OOH = "+ keyEncryptedWithPublicKey);

                    //encrypt object contents using my private key
                    String keyEncryptedWithPublicKeyAndPrivateKey = EncryptionUtil.signDataPrivateKey(keyEncryptedWithPublicKey);

                    //pack data
                    MessageBundle messageBundle = new MessageBundle(keyEncryptedWithPublicKey, keyEncryptedWithPublicKeyAndPrivateKey);

                    Log.w("YES", "0- PLAIN TEXT = " + messageBundle.getPlainText());
                    Log.w("YES", "0- SIGNED TEXT = " + messageBundle.getSignedText());

                    boolean isVerified = EncryptionUtil.verifyData(messageBundle.getPlainText(), messageBundle.getSignedText(), EncryptionUtil.getPublicKey());

                    Log.w("YES", "*_*"+ isVerified);

                    output.writeObject(messageBundle);
                    output.flush();

                    //return the public key
                    return key;
                }
            }
        } catch (ClassNotFoundException classNotFoundException) {
            showToast("Unknown object type received");
            Log.w("YES", "__" +classNotFoundException.getMessage());
        } catch (Exception e) {
            Log.w("YES", "__" + e.getMessage());
        }
        return null;
    }

    private void waitForConnection() throws IOException
    {

        showToast("Waiting for connection");
        connection = server.accept();
        Log.w("YES", "CONNECTED!");
        senderName = connection.getInetAddress().getHostName();
        showToast( "Connection received from: " +
                senderName );
    }

    private void getStreams() throws IOException {
        output = new ObjectOutputStream( connection.getOutputStream() );
        output.flush();
        input = new ObjectInputStream( connection.getInputStream() );
        showToast("Got I/O streams");
    }

    private void processConnection() throws IOException
    {
        Log.w("YES", "PROCSSING!!");
        MessageBundle messageBundle = null;
        do
        {
            try
            {
                //get the object that contains the plain text and signed text
                messageBundle = ( MessageBundle ) input.readObject();

                //decrypt its contents using my private key
                messageBundle.setPlainText(EncryptionUtil.decryptAES(messageBundle.getPlainText(), secretKey));
                messageBundle.setSignedText(EncryptionUtil.decryptAES(messageBundle.getSignedText(), secretKey));

                //decrypt using his public key and compare hashes
                Log.w("YES", "1- PLAIN TEXT = " + messageBundle.getPlainText());
                Log.w("YES", "1- SIGNED TEXT = " + messageBundle.getSignedText());

                boolean isVerified = EncryptionUtil.verifyData(messageBundle.getPlainText(), messageBundle.getSignedText(), senderPublicKey);

                if (isVerified){
                    displayMessage(new Message(messageBundle.getPlainText(), senderName, false));
                }

            }
            catch ( ClassNotFoundException classNotFoundException ) {
                Log.w("YES", "ERROR 1");
                showToast("Unknown object type received");
            } catch (Exception e){
               // Log.w("YES", "Foo didn't work: " + e.getMessage());
            }

        } while (true);
    }

    private void closeConnection()
    {
        showToast( "Closing connection" );
        try
        {
            output.close();
            input.close();
            connection.close();
        }
        catch ( IOException ioException )
        {
            ioException.printStackTrace();
        }
    }

    private void sendData( String message )
    {
        try
        {
            //Encrypt the string using my private key
            String signedText = EncryptionUtil.signDataPrivateKey(message);
            //Log.w("YES", "SIGNED TEXT = " + signedText);
            //pack the plain and signed messages
            MessageBundle messageBundle = new MessageBundle(message, signedText);
            Log.w("YES", "1- PLAIN TEXT = " + messageBundle.getPlainText());
            Log.w("YES", "1- SIGNED TEXT = " + messageBundle.getSignedText());

            //encrypt object contents using symmetric key
            messageBundle.setPlainText(EncryptionUtil.encryptAES(messageBundle.getPlainText(), secretKey));
            messageBundle.setSignedText(EncryptionUtil.encryptAES(messageBundle.getSignedText(), secretKey));

            Log.w("YES", "2- PLAIN TEXT = " + messageBundle.getPlainText());
            Log.w("YES", "2- SIGNED TEXT = " + messageBundle.getSignedText());

            output.writeObject(messageBundle);
            output.flush();
        }
        catch ( IOException ioException )
        {
            showToast("Error writing object");
            Log.w("YES", "ERROR 1 " + ioException.toString());
        }
        catch (Exception e) {
            showToast("Error writing object");
            Log.w("YES", "ERROR 2 " + e.toString());
        }
    }


    private void displayMessage( final Message messageToDisplay )
    {
        runOnUiThread(new Runnable(){
            @Override
            public void run(){
                listMessages.add(messageToDisplay);

                adapter.notifyDataSetChanged();
            }
        });
    }

    private void showToast(final String message) {

        runOnUiThread(new Runnable() {

            @Override
            public void run() {
                Toast.makeText(getApplicationContext(), message,
                        Toast.LENGTH_SHORT).show();
            }
        });
    }

}
