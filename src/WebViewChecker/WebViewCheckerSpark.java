package WebViewChecker;

import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.spark.SparkTransformer;
import soot.options.Options;

import java.io.IOException;
import java.util.*;
import java.util.logging.Logger;

public class WebViewCheckerSpark {

    private static Logger logInfo = Logger.getLogger("WebViewCheckerSpark");

    public static void main(String[] args) throws IOException, XmlPullParserException {

        final ArgumentParser parser = ArgumentParsers.newArgumentParser("WebViewCheckerSpark")
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

        {
            soot.G.reset();

            // set Options
            Options.v().set_src_prec(Options.src_prec_apk);
            Options.v().set_android_jars("./libs/android-platforms");
            // Options.v().set_src_prec(Options.src_prec_java);
            Options.v().set_process_multiple_dex(true);

            // Options.v().set_process_dir(Collections.singletonList(processDir));
            Options.v().set_process_dir(Collections.singletonList(res.get("file").toString()));
            Options.v().set_whole_program(true);
            Options.v().set_allow_phantom_refs(true);
            // Options.v().set_verbose(true);
            Options.v().set_output_format(Options.output_format_none);
            Options.v().set_no_bodies_for_excluded(true);
            Options.v().setPhaseOption("cg.spark", "on");

            enableSpark();

            // set Scene
            Scene.v().loadNecessaryClasses();

            // onCreate in main activity only
            String c = Common.getMainActivityName(res.get("file").toString());
            logInfo.info(c);
            String m = "void onCreate(android.os.Bundle)";
            SootMethod dummyMethod = GenerateDummyClassHelper.doGenerate(c, m);
            if(dummyMethod == null)
                System.exit(1);
            ArrayList entryPoints = new ArrayList();
            entryPoints.add(dummyMethod);
            Scene.v().setEntryPoints(entryPoints);

            PackManager.v().getPack("wjtp").add(
                    new Transform("wjtp.WebViewAnalyzerSpark", new WebViewAnalyzerSpark()));

            Stats.setPreAnalysisEnd();

            // start packs analyse
            PackManager.v().runPacks();
        }

    }

    private static void enableSpark() {
        HashMap opt = new HashMap();
        opt.put("verbose", "true");
        opt.put("propagator", "worklist");
        opt.put("simple-edges-bidirectional", "false");
        opt.put("on-fly-cg", "true");
        opt.put("apponly", "true");
        opt.put("set-impl", "double");
        opt.put("double-set-old", "hybrid");
        opt.put("double-set-new", "hybrid");
        opt.put("enabled", "true");

        SparkTransformer.v().transform("", opt);
    }


}