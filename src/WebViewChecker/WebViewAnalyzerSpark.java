package WebViewChecker;

import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.*;
import java.util.logging.Logger;

import static WebViewChecker.Stats.*;

public class WebViewAnalyzerSpark extends SceneTransformer{

    private static Logger logInfo = Logger.getLogger("WebViewCheckerSpark");

    @Override
    protected void internalTransform(String s, Map<String, String> map) {

        logInfo.info("Start getting the entry.");
        setAnalysisStart();

        CallGraph cg = Scene.v().getCallGraph();
        Set<Edge> visited = new HashSet<>();
        Set<SootMethod> sysMethod = new HashSet<>();

        Common.collectSysMethod(cg, visited, Scene.v().getEntryPoints().get(0), sysMethod);

    }


}
