import net.blueprintforfreespeech.gosling.Gosling;
import net.blueprintforfreespeech.gosling.Gosling.Error;
import net.blueprintforfreespeech.gosling.Gosling.*;

public class Example {
    private static String ENDPOINT_NAME = "test-endpoint";
    private static byte[] EMPTY_BSON = {
        // document length 5 == 0x00000005
        0x05, 0x00, 0x00, 0x00,
        // document null-terminator
        0x00
    };
    private static String CHANNEL_NAME = "test-channel";

    private static class GoslingCallbacks implements
        ITorLogReceivedListener,
        ITorBootstrapStatusReceivedListener,
        IIdentityClientHandshakeChallengeResponseSizeListener,
        IIdentityClientHandshakeBuildChallengeResponseListener,
        IIdentityClientHandshakeCompletedListener,
        IIdentityClientHandshakeFailedListener,
        IIdentityServerPublishedListener,
        IIdentityServerHandshakeClientAllowedListener,
        IIdentityServerEndpointSupportedListener,
        IIdentityServerHandshakeChallengeSizeListener,
        IIdentityServerHandshakeBuildChallengeListener,
        IIdentityServerHandshakeVerifyChallengeResponseListener,
        IIdentityServerHandshakeCompletedListener,
        IIdentityServerHandshakeRejectedListener,
        IIdentityServerHandshakeFailedListener,
        IEndpointClientHandshakeCompletedListener,
        IEndpointClientHandshakeFailedListener,
        IEndpointServerPublishedListener,
        IEndpointServerChannelSupportedListener,
        IEndpointServerHandshakeCompletedListener,
        IEndpointServerHandshakeRejectedListener,
        IEndpointServerHandshakeFailedListener {
        private String name;
        private boolean bootstrapComplete = false;
        private boolean identityServerPublished = false;
        private boolean identityServerHandshakeComplete = false;
        private boolean identityClientHandshakeComplete = false;
        private boolean endpointServerPublished = false;
        private V3OnionServiceId endpointServerServiceId = null;
        private X25519PrivateKey endpointServerClientAuthKey = null;
        private boolean endpointServerHandshakeComplete = false;
        private boolean endpointClientHandshakeComplete = false;
        private java.net.Socket endpointServerSocket = null;
        private java.net.Socket endpointClientSocket = null;
        GoslingCallbacks(String name) {
            this.name = name;
        }

        // Tor Callbacks

        public void onTorLogReceivedEvent(Context context, String line) {
            System.out.println("> " + name + " Tor Log: " + line);
        }

        public void onTorBootstrapStatusReceivedEvent(Context context, long progress, String tag, String summary) {
            System.out.println("> " + name + ": Bootstrap Progress " + progress + "% - " + summary);
            if (progress == 100) {
                this.bootstrapComplete = true;
            }
        }

        // Identity Client Callbacks

        public long onIdentityClientHandshakeChallengeResponseSizeEvent(Context context, long handshake_handle, byte[] challenge_buffer) {
            return Example.EMPTY_BSON.length;
        }
        public void onIdentityClientHandshakeBuildChallengeResponseEvent(Context context, long handshake_handle, byte[] challenge_buffer, byte[] out_challenge_response_buffer) {
            System.out.println("> " + name + ": Builds Client Challenge Response");
            assert out_challenge_response_buffer.length == Example.EMPTY_BSON.length;
            System.arraycopy(Example.EMPTY_BSON, 0, out_challenge_response_buffer, 0, Example.EMPTY_BSON.length);
        }
        public void onIdentityClientHandshakeCompletedEvent(Context context, long handshake_handle, V3OnionServiceId identity_service_id, V3OnionServiceId endpoint_service_id, String endpoint_name, X25519PrivateKey client_auth_private_key) {
            this.identityClientHandshakeComplete = true;
            this.endpointServerServiceId = endpoint_service_id;
            this.endpointServerClientAuthKey = client_auth_private_key;
            System.out.println("> " + this.name + ": Identity Client Handshake Complete");
        }
        public void onIdentityClientHandshakeFailedEvent(Context context, long handshake_handle, Error error) {
            System.out.println("> " + name + ": Client Handshake Failed");
            System.out.println(" > " + Gosling.errorGetMessage(error));
        }

        // Identity Server Callbacks

        public void onIdentityServerPublishedEvent(Context context) {
            this.identityServerPublished = true;
            System.out.println("> " + name + ": Identity Server Published");
        }
        public boolean onIdentityServerHandshakeClientAllowedEvent(Context context, long handshake_handle, V3OnionServiceId client_service_id) {
            return true;
        }
        public boolean onIdentityServerEndpointSupportedEvent(Context context, long handshake_handle, String endpoint_name) {
            System.out.println("> " + name + ": Identity Client requested '" + endpoint_name + "'");
            return endpoint_name.equals(Example.ENDPOINT_NAME);
        }
        public long onIdentityServerHandshakeChallengeSizeEvent(Context context, long handshake_handle) {
            return Example.EMPTY_BSON.length;
        }
        public void onIdentityServerHandshakeBuildChallengeEvent(Context context, long handshake_handle, byte[] out_challenge_buffer) {
            System.out.println("> " + this.name + ": Builds Server Challenge");
            assert out_challenge_buffer.length == Example.EMPTY_BSON.length;
            System.arraycopy(Example.EMPTY_BSON, 0, out_challenge_buffer, 0, Example.EMPTY_BSON.length);
        }
        public boolean onIdentityServerHandshakeVerifyChallengeResponseEvent(Context context, long handshake_handle, byte[] challenge_response_buffer) {
            return true;
        }

        public void onIdentityServerHandshakeCompletedEvent(Context context, long handshake_handle, Ed25519PrivateKey endpoint_private_key, String endpoint_name, V3OnionServiceId client_service_id, X25519PublicKey client_auth_public_key) {
            this.identityServerHandshakeComplete = true;
            System.out.println("> " + this.name + ": Identity Server Handshake Complete");
            System.out.println("> " + this.name + ": Starting Endpoint Server");

            Out<Error> outError = new Out<Error>();
            Gosling.contextStartEndpointServer(context, endpoint_private_key, endpoint_name, client_service_id, client_auth_public_key, outError);
            if (!outError.isEmpty()) {
                System.out.println("error: " + Gosling.errorGetMessage(outError.get()));
                System.exit(1);
            }
        }

        public void onIdentityServerHandshakeRejectedEvent(Context context, long handshake_handle, boolean client_allowed, boolean client_requested_endpoint_valid, boolean client_proof_signature_valid, boolean client_auth_signature_valid, boolean challenge_response_valid) {
            System.out.println("> " + this.name + ": Identity Server Rejects Handshake");
            System.out.println(" > client_allowed: " + client_allowed);
            System.out.println(" > client_requested_endpoint_valid: " + client_requested_endpoint_valid);
            System.out.println(" > client_proof_signature_valid: " + client_proof_signature_valid);
            System.out.println(" > client_auth_signature_valid: " + client_auth_signature_valid);
            System.out.println(" > challenge_response_valid: " + challenge_response_valid);
            System.exit(1);
        }

        public void onIdentityServerHandshakeFailedEvent(Context context, long handshake_handle, Error error) {
            System.out.println("> " + this.name + ": Identity Server Handshake Failed");
            System.out.println(" > " + Gosling.errorGetMessage(error));
            System.exit(1);
        }

        // Endpoint Client Callbacks
        public void onEndpointClientHandshakeCompletedEvent(Context context, long handshake_handle, V3OnionServiceId endpoint_service_id, String channel_name, java.net.Socket stream) {
            this.endpointClientHandshakeComplete = true;
            this.endpointClientSocket = stream;
            System.out.println("> " + this.name + ": Endpoint Client Handshake Completed!");
        }

        public void onEndpointClientHandshakeFailedEvent(Context context, long handshake_handle, Error error) {
            System.out.println("> " + this.name + ": Endpoint Client Handshake Failed");
            System.out.println(" > " + Gosling.errorGetMessage(error));
            System.exit(1);
        }

        // Endpoint Server Callbacks

        public void onEndpointServerPublishedEvent(Context context, V3OnionServiceId enpdoint_service_id, String endpoint_name) {
            this.endpointServerPublished = true;
            System.out.println("> " + this.name + ": Endpoint Server Published");
        }

        public boolean onEndpointServerChannelSupportedEvent(Context context, long handshake_handle, V3OnionServiceId client_service_id, String channel_name) {
            System.out.println("> " + name + ": Endpoint Client requested '" + channel_name + "'");
            return channel_name.equals(Example.CHANNEL_NAME);
        }

        public void onEndpointServerHandshakeCompletedEvent(Context context, long handshake_handle, V3OnionServiceId endpoint_service_id, V3OnionServiceId client_service_id, String channel_name, java.net.Socket stream) {
            this.endpointServerHandshakeComplete = true;
            this.endpointServerSocket = stream;
            System.out.println("> " + this.name + ": Endpoint Server Handshake Completed!");
        }

        public void onEndpointServerHandshakeRejectedEvent(Context context, long handshake_handle, boolean client_allowed, boolean client_requested_channel_valid, boolean client_proof_signature_valid) {
            System.out.println("> " + this.name + ": Endpoint Server Rejects Handshake");
            System.out.println(" > client_allowed: " + client_allowed);
            System.out.println(" > client_requested_channel_valid: " + client_requested_channel_valid);
            System.out.println(" > client_proof_signature_valid: " + client_proof_signature_valid);
            System.exit(1);
        }

        public void onEndpointServerHandshakeFailedEvent(Context context, long handshake_handle, Error error) {
            System.out.println("> " + this.name + ": Endpoint Server Handshake Failed");
            System.out.println(" > " + Gosling.errorGetMessage(error));
            System.exit(1);
        }
    }

    private static void handleOutError(Out<Error> outError) throws Exception {
        if (!outError.isEmpty()) {
            throw new Exception("error: " + Gosling.errorGetMessage(outError.get()));
        }
    }

    public static void main(String[] args) {
        System.out.println("Hello from Java!");

        // Alice and Bob create a Gosling Context
        // Bob starts Identity Server
        // Alice Requests Endpoint from Bob
        // Alice Connects to Bob's Endpoint
        // Alice and Bob send messages to each other

        try {

            System.out.println("Init Gosling Library");

            Out<Library> outLibrary = new Out<Library>();
            Out<Error> outError = new Out<Error>();
            Gosling.libraryInit(outLibrary, outError);
            handleOutError(outError);

            System.out.println("Create Identity Keys");

            Out<Ed25519PrivateKey> outAliceIdKey = new Out<Ed25519PrivateKey>();
            Gosling.ed25519PrivateKeyGenerate(outAliceIdKey, outError);
            handleOutError(outError);
            Ed25519PrivateKey aliceIdKey = outAliceIdKey.get();
            assert aliceIdKey != null;

            Out<Ed25519PrivateKey> outBobIdKey = new Out<Ed25519PrivateKey>();
            Gosling.ed25519PrivateKeyGenerate(outBobIdKey, outError);
            handleOutError(outError);
            Ed25519PrivateKey bobIdKey = outBobIdKey.get();
            assert bobIdKey != null;

            System.out.println("Start Tor Clients");

            Out<TorProvider> outAliceTorProvider = new Out<TorProvider>();
            Gosling.torProviderNewLegacyClient(outAliceTorProvider, null, "/tmp/java-test-alice", outError);
            handleOutError(outError);
            TorProvider aliceTorProvider = outAliceTorProvider.get();
            assert aliceTorProvider != null;

            Out<TorProvider> outBobTorProvider = new Out<TorProvider>();
            Gosling.torProviderNewLegacyClient(outBobTorProvider, null, "/tmp/java-test-bob", outError);
            handleOutError(outError);
            TorProvider bobTorProvider = outBobTorProvider.get();
            assert bobTorProvider != null;

            System.out.println("Creating Context");
            Out<Context> outAliceContext = new Out<Context>();
            Gosling.contextInit(outAliceContext, aliceTorProvider, 1120, 401, aliceIdKey, outError);
            handleOutError(outError);
            Context aliceContext = outAliceContext.get();
            assert aliceContext != null;

            Out<Context> outBobContext = new Out<Context>();
            Gosling.contextInit(outBobContext, bobTorProvider, 1120, 401, bobIdKey, outError);
            handleOutError(outError);
            Context bobContext = outBobContext.get();
            assert bobContext != null;

            System.out.println("Registering Callbacks");
            // Alice client-only callbacks
            GoslingCallbacks aliceCallbacks = new GoslingCallbacks("Alice");
            Gosling.contextSetTorLogReceivedCallback(aliceContext, aliceCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetTorBootstrapStatusReceivedCallback(aliceContext, aliceCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityClientChallengeResponseSizeCallback(aliceContext, aliceCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityClientBuildChallengeResponseCallback(aliceContext, aliceCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityClientHandshakeCompletedCallback(aliceContext, aliceCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityClientHandshakeFailedCallback(aliceContext, aliceCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetEndpointClientHandshakeCompletedCallback(aliceContext, aliceCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetEndpointClientHandshakeFailedCallback(aliceContext, aliceCallbacks, outError);
            handleOutError(outError);

            // Bob server-only callbacks
            GoslingCallbacks bobCallbacks = new GoslingCallbacks("Bob");
            Gosling.contextSetTorLogReceivedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityServerPublishedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetTorBootstrapStatusReceivedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityServerClientAllowedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityServerEndpointSupportedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityServerChallengeSizeCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityServerBuildChallengeCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityServerVerifyChallengeResponseCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityServerHandshakeCompletedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityServerHandshakeRejectedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetIdentityServerHandshakeFailedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetEndpointServerPublishedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetEndpointServerChannelSupportedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetEndpointServerHandshakeCompletedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetEndpointServerHandshakeRejectedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);
            Gosling.contextSetEndpointServerHandshakeFailedCallback(bobContext, bobCallbacks, outError);
            handleOutError(outError);

            System.out.println("Bootstrap Tor Daemons");

            Gosling.contextBootstrapTor(aliceContext, outError);
            handleOutError(outError);
            Gosling.contextBootstrapTor(bobContext, outError);
            handleOutError(outError);

            while (!aliceCallbacks.bootstrapComplete ||
                   !bobCallbacks.bootstrapComplete) {
                Gosling.contextPollEvents(aliceContext, outError);
                handleOutError(outError);
                Gosling.contextPollEvents(bobContext, outError);
                handleOutError(outError);
            }

            System.out.println("Bob Starts Identity Server");
            Gosling.contextStartIdentityServer(bobContext, outError);
            handleOutError(outError);

            while (!bobCallbacks.identityServerPublished) {
                Gosling.contextPollEvents(bobContext, outError);
                handleOutError(outError);
            }

            System.out.println("Alice Begins Identity Handshake");

            Out<V3OnionServiceId> outBobIdServiceId = new Out<V3OnionServiceId>();
            Gosling.v3OnionServiceIdFromEd25519PrivateKey(outBobIdServiceId, bobIdKey, outError);
            handleOutError(outError);
            V3OnionServiceId bobIdServiceId = outBobIdServiceId.get();
            assert bobIdServiceId != null;

            long aliceIdentityHandshakeHandle = Gosling.contextBeginIdentityHandshake(aliceContext, bobIdServiceId, Example.ENDPOINT_NAME, outError);
            handleOutError(outError);

            // wait for identity handshake to complete
            while (!aliceCallbacks.identityClientHandshakeComplete ||
                   !bobCallbacks.identityServerHandshakeComplete) {
                Gosling.contextPollEvents(aliceContext, outError);
                handleOutError(outError);
                Gosling.contextPollEvents(bobContext, outError);
                handleOutError(outError);
            }

            V3OnionServiceId bobEndpointServerServiceId = aliceCallbacks.endpointServerServiceId;
            X25519PrivateKey bobEndpointServerClientAuthKey = aliceCallbacks.endpointServerClientAuthKey;

            // wait for endpoint server to publish
            while (!bobCallbacks.endpointServerPublished) {
                Gosling.contextPollEvents(bobContext, outError);
                handleOutError(outError);
            }

            System.out.println("Alice Begins Endpoint Handshake");

            Gosling.contextBeginEndpointHandshake(aliceContext, bobEndpointServerServiceId, bobEndpointServerClientAuthKey, Example.CHANNEL_NAME, outError);
            handleOutError(outError);

            while (!aliceCallbacks.endpointClientHandshakeComplete ||
                   !bobCallbacks.endpointServerHandshakeComplete) {
                Gosling.contextPollEvents(aliceContext, outError);
                handleOutError(outError);
                Gosling.contextPollEvents(bobContext, outError);
                handleOutError(outError);
            }

            assert aliceCallbacks.endpointClientSocket != null;
            assert bobCallbacks.endpointServerSocket != null;

            java.io.OutputStreamWriter aliceOut = new java.io.OutputStreamWriter(aliceCallbacks.endpointClientSocket.getOutputStream());
            java.io.BufferedReader aliceIn = new java.io.BufferedReader(new java.io.InputStreamReader(aliceCallbacks.endpointClientSocket.getInputStream()));

            aliceOut.write("Hello Bob!\n");
            aliceOut.flush();

            java.io.OutputStreamWriter bobOut = new java.io.OutputStreamWriter(bobCallbacks.endpointServerSocket.getOutputStream());
            java.io.BufferedReader bobIn = new java.io.BufferedReader(new java.io.InputStreamReader(bobCallbacks.endpointServerSocket.getInputStream()));

            bobOut.write("Hello Alice!\n");
            bobOut.flush();

            System.out.println("Alice Received: '" + aliceIn.readLine() + "'");
            System.out.println("Bob Received: '" + bobIn.readLine() + "'");


            String characters = "0123456789abcdef";
            char[] randomCharArray = new char[128];
            java.util.Random random = new java.util.Random();

            // Populate the char array with random characters
            for (int i = 0; i < randomCharArray.length; i++) {
                int randomIndex = random.nextInt(characters.length());
                randomCharArray[i] = characters.charAt(randomIndex);
            }
            String randomStringWrite = new String(randomCharArray);
            aliceOut.write(randomStringWrite);
            aliceOut.write("\n");
            aliceOut.flush();

            System.out.println("Alice Wrote: '" + randomStringWrite + "'");

            String randomStringRead = bobIn.readLine();
            System.out.println("Bob Read:    '" + randomStringRead + "'");

            System.out.println("Write == Read : " + randomStringWrite.equals(randomStringRead));

        } catch (Exception ex) {
            System.out.println(ex.toString());
        }

        System.gc();
        System.runFinalization();
    }
}