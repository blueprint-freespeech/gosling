import net.blueprintforfreespeech.gosling.Gosling;
import net.blueprintforfreespeech.gosling.Gosling.Error;
import net.blueprintforfreespeech.gosling.Gosling.*;

public class GoslingTest {
    private static void handleOutError(Out<Error> outError) throws Exception {
        if (!outError.isEmpty()) {
            throw new Exception("error: " + Gosling.errorGetMessage(outError.get()));
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Hello from Java!");

        System.out.println("Init Gosling Library");

        Out<Library> outLibrary = new Out<Library>();
        Out<Error> outError = new Out<Error>();
        Gosling.libraryInit(outLibrary, outError);
        handleOutError(outError);

        System.gc();
        System.runFinalization();
    }
}
