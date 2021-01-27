package WebViewChecker;

import soot.Modifier;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.entryPointCreators.SequentialEntryPointCreator;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/*
can use createDummyMain directly, however,
this class can issue hints if wrong class name or method name is given.
 */

public class GenerateDummyClassHelper {
    private static Logger logInfo = Logger.getLogger("WebViewChecker");

    static SootMethod doGenerate(String classNameSignature, String methodSignature)
    {
        SootClass sc = Scene.v().loadClassAndSupport(classNameSignature);
        sc.setApplicationClass();

        if (sc.declaresMethod(methodSignature) == false)
        {
            logInfo.warning("Cannot find method: " + methodSignature);
            logInfo.warning("Alternative methods list:");

            for (SootMethod m: sc.getMethods())
                logInfo.warning(m.toString());
            return null;
        }

        // invoke flowdroid to generate a dummy method
        List<String> e = new ArrayList<String>();
        e.add("<" + classNameSignature + ": " + methodSignature + ">");
        SequentialEntryPointCreator sequentialEntryPointCreator = new SequentialEntryPointCreator(e);
        SootMethod m = sequentialEntryPointCreator.createDummyMain();

        return m;
    }
}
