package WebViewChecker;

import java.util.ArrayList;

public class Stats {

    static long preAnalysisStart = 0;
    static long preAnalysisEnd = 0;
    static long analysisStart = 0;
    static long analysisEnd = 0;

    static void setPreAnalysisStart() { preAnalysisStart = System.currentTimeMillis();}
    static void setPreAnalysisEnd() { preAnalysisEnd = System.currentTimeMillis();}
    static void setAnalysisStart() { analysisStart = System.currentTimeMillis();}
    static void setAnalysisEnd() { analysisEnd = System.currentTimeMillis();}

    static void dumpTimeInfo()
    {
        System.out.println("----------------------------------------------------------");
        System.out.println("Pre-analysis takes " + (preAnalysisEnd - preAnalysisStart) + " ms");
        System.out.println("Analysis takes " + (analysisEnd - analysisStart) + " ms");
        System.out.println("----------------------------------------------------------");
    }

}
