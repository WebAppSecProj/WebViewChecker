package WebViewChecker;

import fj.data.Array;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlHandler;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.android.resources.ARSCFileParser;
import soot.jimple.internal.JVirtualInvokeExpr;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.ide.icfg.AbstractJimpleBasedICFG;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.jimple.toolkits.ide.icfg.OnTheFlyJimpleBasedICFG;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.io.IOException;
import java.util.*;
import java.util.logging.Logger;


public class Common {
    private static Logger logInfo = Logger.getLogger("Common");

    public static String apkFile = "";

    public static List<HashMap> entryInfo = new ArrayList<>();


    public static void fillEntry()
    {
        for(HashMap m: entryInfo)
        {
            if(m.get("soot_method") == null || m.get("application_method") == null || m.get("icfg") == null)
            {
                m.put("soot_method", GenerateDummyClassHelper.doGenerate((String)m.get("class"), (String)m.get("method")));

                Set<SootMethod> applicationMethod = new HashSet<>();
                OnTheFlyJimpleBasedICFG onTheFlyJimpleBasedICFG = new OnTheFlyJimpleBasedICFG((SootMethod) m.get("soot_method"));
                m.put("icfg", onTheFlyJimpleBasedICFG);

                collectApplicationMethod(onTheFlyJimpleBasedICFG, applicationMethod, (SootMethod) m.get("soot_method"));
                m.put("application_method", applicationMethod);
            }
        }
    }

    public static String getResource(int id){
        ARSCFileParser arscFileParser = new ARSCFileParser();
        try {
            arscFileParser.parse(apkFile);
        } catch (IOException e) {
            e.printStackTrace();
        }

        ARSCFileParser.AbstractResource retMe = arscFileParser.findResource(id);
        return retMe.toString();

    }

    /**
     * Get the name of the main activity in the AndroidManifest.xml file
     * @param apkFile
     * @return
     * ref: https://github.com/secure-software-engineering/DroidForce/blob/master/Instrumentation-PEP/src/de/ecspride/util/UpdateManifestAndCodeForWaitPDP.java
     */
    public static String getMainActivityName(String apkFile){

        String mainActivityName = null;
        try {
            ProcessManifest pm = new ProcessManifest(apkFile);
            AXmlHandler axmlh = pm.getAXml();

            // Find main activity and remove main intent-filter
            List<AXmlNode> anodes = axmlh.getNodesWithTag("activity");
            for (AXmlNode an: anodes) {
                boolean hasMain = false;
                boolean hasLauncher = false;
                AXmlNode filter = null;

                AXmlAttribute aname = an.getAttribute("name");
                String aval = (String)aname.getValue();
                logInfo.info("activity: "+ aval);
                for (AXmlNode ch : an.getChildren()) {
                    logInfo.info("children: "+ ch);
                }
                List<AXmlNode> fnodes = an.getChildrenWithTag("intent-filter");
                for (AXmlNode fn: fnodes) {

                    hasMain = false;
                    hasLauncher = false;

                    // check action
                    List<AXmlNode> acnodes = fn.getChildrenWithTag("action");
                    for (AXmlNode acn: acnodes) {
                        AXmlAttribute acname = acn.getAttribute("name");
                        String acval = (String)acname.getValue();
                        logInfo.info("action: "+ acval);
                        if (acval.equals("android.intent.action.MAIN")) {
                            hasMain = true;
                        }
                    }
                    // check category
                    List<AXmlNode> catnodes = fn.getChildrenWithTag("category");
                    for (AXmlNode catn: catnodes) {
                        AXmlAttribute catname = catn.getAttribute("name");
                        String catval = (String)catname.getValue();
                        logInfo.info("category: "+ catval);
                        if (catval.equals("android.intent.category.LAUNCHER")) {
                            hasLauncher = true;
                            filter = fn;
                        }
                    }
                    if (hasLauncher && hasMain) {
                        break;
                    }
                }

                if (hasLauncher && hasMain) {
                    // replace name with the activity waiting for the connection to the PDP
                    logInfo.info("main activity is: "+ aval);
                    logInfo.info("excluding filter: "+ filter);
                    filter.exclude();
                    mainActivityName = aval;
                    break;
                }

            }
        } catch (IOException | XmlPullParserException ex) {
            logInfo.warning("Could not read Android manifest file: " + ex.getMessage());
            throw new RuntimeException(ex);
        }
        return mainActivityName;
    }

    /**
     * 判断一个字符串是否为url
     * @param str String 字符串
     * @return boolean 是否为url
     * @author peng1 chen
     * **/

    public static boolean isURL(String str){
        //转换为小写
        str = str.toLowerCase();
        String regex = "^((https|http|ftp|rtsp|mms)?://)"  //https、http、ftp、rtsp、mms
                + "?(([0-9a-z_!~*'().&=+$%-]+: )?[0-9a-z_!~*'().&=+$%-]+@)?" //ftp的user@
                + "(([0-9]{1,3}\\.){3}[0-9]{1,3}" // IP形式的URL- 例如：199.194.52.184
                + "|" // 允许IP和DOMAIN（域名）
                + "([0-9a-z_!~*'()-]+\\.)*" // 域名- www.
                + "([0-9a-z][0-9a-z-]{0,61})?[0-9a-z]\\." // 二级域名
                + "[a-z]{2,6})" // first level domain- .com or .museum
                + "(:[0-9]{1,5})?" // 端口号最大为65535,5位数
                + "((/?)|" // a slash isn't required if there is no file name
                + "(/[0-9a-z_!~*'().;?:@&=+$,%#-]+)+/?)$";
        return  str.matches(regex);
    }

    // collect OnCreate related methods, such that analysis can be limited to these methods.
    public static void collectApplicationMethod(AbstractJimpleBasedICFG icfg, Set<SootMethod> applicationMethod, SootMethod curMethod)
    {
        applicationMethod.add(curMethod);
        Body b = curMethod.retrieveActiveBody();
        UnitGraph ug = new BriefUnitGraph(b);
        Iterator<Unit> it = ug.iterator();

        while(it.hasNext())
        {
            Unit u = it.next();
            if(icfg.isCallStmt(u)){
//                if(u.toString().contains("postDelayed"))
//                {
//                    logInfo.info("placeholder");
//                }
                for (SootMethod callee : icfg.getCalleesOfCallAt(u)) {
                    // logInfo.info("M" + callee.toString());
                    if (callee.getDeclaringClass().isApplicationClass()) {
                        // System.out.println(curMethod.toString() + ": " +u.toString() + " -> " + callee.toString());
                        // native method?
                        if (callee.hasActiveBody() == false)
                            continue;
//                        if (callee.getName().contains("<clinit>"))
//                            continue;
                        if (applicationMethod.contains(callee))
                            continue;
                        collectApplicationMethod(icfg, applicationMethod, callee);
                    }
                }
            }
        }
    }

    @Deprecated
    public static void collectSysMethod(CallGraph cg, Set<Edge> visited, SootMethod m, Set<SootMethod> sysMethod) {
        Iterator<Edge> it = cg.edgesOutOf(m);
        while(it.hasNext()) {
            Edge e = it.next();
            if (visited.contains(e)) continue;
            visited.add(e);
            logInfo.info(e.tgt().toString());
            if (e.tgt().getDeclaringClass().isApplicationClass())
                collectSysMethod(cg, visited, e.tgt(), sysMethod);
            else
                sysMethod.add(e.tgt());
        }
    }

    @Deprecated
    public static SootMethod searchMethod(String classNameSignature, String methodSignature)
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
        return sc.getMethod(methodSignature);
    }
}
