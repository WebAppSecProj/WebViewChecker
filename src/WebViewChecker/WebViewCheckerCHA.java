package WebViewChecker;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.options.Options;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.logging.Logger;

public class WebViewCheckerCHA {

    private static Logger logInfo = Logger.getLogger("WebViewCheckerCHA");

    public static void main(String[] args) throws IOException, XmlPullParserException {

        Stats.setPreAnalysisStart();

        final ArgumentParser parser = ArgumentParsers.newArgumentParser("WebViewCheckerCHA")
                .defaultHelp(true)
                .description("Distill argument of WebView.");
        parser.addArgument("-f", "--file")
                .dest("file")
                .required(true)
                .help("APK file to check");

        Namespace res = null;
        try {
            res = parser.parseArgs(args);
            logInfo.info("processing file: " + res.get("file").toString());

        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(1);
        }

        Common.apkFile = res.get("file").toString();

        {
            G.reset();

            // set Options
            Options.v().set_src_prec(Options.src_prec_apk);
            Options.v().set_android_jars("./libs/android-platforms");
            // Options.v().set_src_prec(Options.src_prec_java);
            Options.v().set_process_multiple_dex(true);

            // Options.v().set_process_dir(Collections.singletonList(processDir));
            Options.v().set_process_dir(Collections.singletonList(Common.apkFile));
            Options.v().set_whole_program(true);
            Options.v().set_allow_phantom_refs(true);
            // Options.v().set_verbose(true);
            Options.v().set_output_format(Options.output_format_none);
            Options.v().set_no_bodies_for_excluded(true);
            Options.v().setPhaseOption("cg", "safe-newinstance:true");
            Options.v().setPhaseOption("cg.cha","enabled:true");
            
            // set Scene
            Scene.v().loadNecessaryClasses();
            loadBody();

            // onCreate in main activity only
            String c = Common.getMainActivityName(Common.apkFile);
            logInfo.info(c);
            String m = "void onCreate(android.os.Bundle)";
            SootMethod dummyMethod = GenerateDummyClassHelper.doGenerate(c, m);

            HashMap e = new HashMap();
            e.put("class", c);
            e.put("method", m);
            e.put("soot_method", null);
            e.put("application_method", null);
            e.put("icfg", null);
            Common.entryInfo.add(e);

            if(dummyMethod == null)
                System.exit(1);
            ArrayList entryPoints = new ArrayList();
            entryPoints.add(dummyMethod);
            Scene.v().setEntryPoints(entryPoints);

            PackManager.v().getPack("wjtp").add(
                    new Transform("wjtp.WebViewAnalyzerCHA", new WebViewAnalyzerCHA()));

            Stats.setPreAnalysisEnd();

            // start packs analyse
            PackManager.v().runPacks();
            Stats.dumpTimeInfo();
        }
    }

    private static void loadBody() {
        for(SootClass c: Scene.v().getClasses()) {
            for (SootMethod m : c.getMethods()) {
                // https://mailman.cs.mcgill.ca/pipermail/soot-list/2006-January/000472.html
                if (m.hasActiveBody() == false) {
                    try {
                        m.retrieveActiveBody();
                    } catch (Exception e) {

                    }
                }
            }
        }
    }

}