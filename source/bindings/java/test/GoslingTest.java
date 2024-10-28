public class GoslingTest {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello from Java!");

        GoslingHandshake.run();

        System.gc();
        System.runFinalization();
    }
}
