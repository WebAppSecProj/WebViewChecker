package WebViewChecker;

import heros.IFDSTabulationProblem;
import heros.InterproceduralCFG;
import heros.solver.IFDSSolver;
import soot.*;
import soot.dexpler.DalvikThrowAnalysis;
import soot.jimple.*;
import soot.jimple.internal.JVirtualInvokeExpr;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.ide.exampleproblems.IFDSReachingDefinitions;
import soot.jimple.toolkits.ide.icfg.AbstractJimpleBasedICFG;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.jimple.toolkits.ide.icfg.OnTheFlyJimpleBasedICFG;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.DirectedGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.Pair;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.toolkits.scalar.SimpleLocalUses;
import soot.toolkits.scalar.UnitValueBoxPair;

import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebViewAnalyzerCHA extends SceneTransformer{

    private static Logger logInfo = Logger.getLogger("WebViewCheckerCHA");


    @Override
    protected void internalTransform(String s, Map<String, String> map) {

        Stats.setAnalysisStart();

        // Notes that the JimpleBasedInterproceduralCFG is more precise than that the OnTheFlyJimpleBasedICFG.
        // e.g., in the example of a3ec5b6abe04471d3311a157ed1ae852.apk
        // the callee of `new Handler().postDelayed(new SplashHandler(), 5000);` can be solved by using JimpleBasedInterproceduralCFG, but not OnTheFlyJimpleBasedICFG.
        // <com.fuge.tradex.LauncherActivity: void onCreate(android.os.Bundle)>: virtualinvoke $r13.<android.os.Handler: boolean postDelayed(java.lang.Runnable,long)>($r14, 5000L) -> <com.fuge.tradex.LauncherActivity$SplashHandler: void run()>
        JimpleBasedInterproceduralCFG icfg_t = new JimpleBasedInterproceduralCFG(false, true);
        Set<SootMethod> applicationMethodO = new HashSet<>();
        Common.collectApplicationMethod(icfg_t, applicationMethodO, Scene.v().getEntryPoints().get(0));
        // Common.fillEntry();
        Common.entryInfo.get(0).put("soot_method", Scene.v().getEntryPoints().get(0));
        Common.entryInfo.get(0).put("icfg", icfg_t);
        Common.entryInfo.get(0).put("application_method", applicationMethodO);

        // the main activity commonly behind the splash activity, so I only scan one iteration.
        // the rational behind the code is that:
        // the splash activity will start main activity through StartActivity and main activity is delivered via an Intent parameter.
        // Note that, the workflow of starting an activity is: S1. New Intent, S2. Init the Intent with main activity class, S3. StartActivity.
        // If I use reaching-definition, we will reach S1 such that miss the main activity class of S2, so, I use def-use chain instead.

        // for(SootMethod m: applicationMethodO) {
        for(SootMethod m: (Set<SootMethod>)Common.entryInfo.get(0).get("application_method")) {
            if (!m.hasActiveBody())
                continue;

            Iterator<Unit> it = m.getActiveBody().getUnits().iterator();
            while (it.hasNext()) {
                Unit u = it.next();

                BriefUnitGraph briefUnitGraph = new BriefUnitGraph(m.getActiveBody());
                SimpleLocalDefs simpleLocalDefs = new SimpleLocalDefs(briefUnitGraph);
                SimpleLocalUses simpleLocalUses = new SimpleLocalUses(briefUnitGraph, simpleLocalDefs);
                List<UnitValueBoxPair> uses = simpleLocalUses.getUsesOf(u);

                boolean isStartActivity = false;
                boolean isNewIntent = false;
                String className = null;

                for (UnitValueBoxPair l : uses) {
                    Stmt stmt = (Stmt) l.getUnit();
                    if (!stmt.containsInvokeExpr()) {
                        continue;
                    }
                    for (SootMethod callee : ((AbstractJimpleBasedICFG) Common.entryInfo.get(0).get("icfg")).getCalleesOfCallAt(stmt)) {
                    // for (SootMethod callee : icfg_t.getCalleesOfCallAt(stmt)) {
                        // supplement the applicationMethod
                        logInfo.info(callee.getSignature());
                        logInfo.info(stmt.toString());
                        if (callee.getSignature().equals("<android.app.Activity: void startActivity(android.content.Intent)>")) {
                            isStartActivity = true;
                        }
                        if (callee.getSignature().equals("<android.content.Intent: void <init>(android.content.Context,java.lang.Class)>")) {
                            isNewIntent = true;
                            InvokeExpr expr = stmt.getInvokeExpr();
                            className = expr.getArg(1).toString();
                        }

                        logInfo.info(l.getUnit().toString());
                    }
                }
                if(isNewIntent && isStartActivity && className != null)
                {
                    //1. find the SootMethod
                    logInfo.info(className);
                    Pattern r = Pattern.compile("class \"L(.*);\"");

                    Matcher matcher = r.matcher(className);
                    if (matcher.find( )) {
                        className = matcher.group(1);
                    } else {
                        logInfo.warning("NO MATCH");
                    }

                    HashMap e = new HashMap();
                    e.put("class", className.replace("/", "."));
                    e.put("method", "void onCreate(android.os.Bundle)");
                    e.put("soot_method", null);
                    e.put("application_method", null);
                    e.put("icfg", null);
                    Common.entryInfo.add(e);

                }
            }
        }

        Common.fillEntry();

        for(HashMap i: Common.entryInfo) {
            Set<SootMethod> applicationMethod = (Set<SootMethod>) i.get("application_method");
            AbstractJimpleBasedICFG icfg = (AbstractJimpleBasedICFG) i.get("icfg");

            for(SootMethod m: applicationMethod)
            {
                if(!m.hasActiveBody())
                    continue;

                // https://www.sable.mcgill.ca/soot/tutorial/profiler2/index.html

                Iterator<Unit> it = m.getActiveBody().getUnits().iterator();
                while(it.hasNext())
                {
                    Stmt stmt = (Stmt)it.next();
                    logInfo.info(stmt.toString());
                    if (!stmt.containsInvokeExpr()) {
                        continue;
                    }
                    for (SootMethod callee : icfg.getCalleesOfCallAt(stmt)) {
                        // query goes here
                        logInfo.info("sig: " + callee.getSignature());

                        if(callee.getSignature().equals("<android.webkit.WebView: void loadUrl(java.lang.String)>"))
                        {
                            Set<String> urls = new HashSet<>();
                            InvokeExpr expr = stmt.getInvokeExpr();
                            Value v = expr.getArg(0);
                            logInfo.info(m.toString());
                            this.searchConst(v, stmt, m, urls);
                            logInfo.info(urls.toString());
                        }
                    }
                }
            }

        }
        Stats.setAnalysisEnd();
    }

    // yes, I use `search` instead of analysis. It's now a coarse analysis.
    // https://www.programcreek.com/java-api-examples/?api=soot.jimple.InstanceFieldRef
    // http://www.sable.mcgill.ca/soot/tutorial/phase/index.html
    // https://mailman.cs.mcgill.ca/pipermail/soot-list/2014-March/006698.html

    private void searchConst(Value value, Unit stmt, SootMethod sootMethod, Set<String> urls) {
        // test case: "./testcase/a3ec5b6abe04471d3311a157ed1ae852.apk"
        // test case: "./testcase/435738b93f9baed84b62400996ef07a3.apk"

        // logInfo.info(value.getClass().toString());

        if (value instanceof Local) {
            BriefUnitGraph briefUnitGraph = new BriefUnitGraph(sootMethod.getActiveBody());
            SimpleLocalDefs simpleLocalDefs = new SimpleLocalDefs(briefUnitGraph);
            List<Unit> defs = simpleLocalDefs.getDefsOfAt((Local) value, stmt);
            // get all defs
            for (Unit u : defs) {
                Stmt s = (Stmt) u;

                AssignStmt as = (AssignStmt) s;
                Value v = as.getRightOp();
                // logInfo.info(v.getClass().toString());
                if (v instanceof JVirtualInvokeExpr) {
                    JVirtualInvokeExpr vt = (JVirtualInvokeExpr) v;
                    if(vt.getMethod().getSignature().equals("<android.content.Context: java.lang.String getString(int)>")) {
                        if(vt.getArg(0) instanceof IntConstant) {
                            String r = Common.getResource(((IntConstant) vt.getArg(0)).value);
                            if (Common.isURL(r))
                                urls.add(r);
                        }
                    }
                }
                if (v instanceof StaticFieldRef) {
                    searchConst(v, s, null, urls);
                }
                if (v instanceof Local) {
                    logInfo.info("TODO");
                }
            }
        }

        if (value instanceof StaticFieldRef)
        {
            StaticFieldRef vt = (StaticFieldRef) value;
            List<ValueBox> vb = vt.getUseBoxes();
            SootField sf = vt.getField();
            // TODO:: how to obtain all references to a SootField?
            logInfo.info("placeholder");

        }
    }


}
