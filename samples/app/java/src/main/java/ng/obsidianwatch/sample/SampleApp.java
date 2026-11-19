package ng.obsidianwatch.sample;

import io.opentelemetry.api.trace.Span;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * ObsidianWatch sample application - Java (Spring Boot + OpenTelemetry Java agent).
 * INTENTIONALLY VULNERABLE (fake SQL layer, debug shell endpoint). Refuses to start unless
 * OW_ALLOW_VULN_DEMO=1 and binds 127.0.0.1 only. Never deploy it. See docs/app/setup-java.md.
 */
@SpringBootApplication
@RestController
public class SampleApp {
    public static class SqlSyntaxException extends RuntimeException {
        SqlSyntaxException(String m) { super(m); }
    }

    public static void main(String[] args) {
        if (!"1".equals(System.getenv("OW_ALLOW_VULN_DEMO"))) {
            System.err.println("This sample is intentionally vulnerable. Set OW_ALLOW_VULN_DEMO=1 to run it (binds 127.0.0.1 only).");
            System.exit(1);
        }
        System.setProperty("server.address", "127.0.0.1");
        System.setProperty("server.port", System.getenv().getOrDefault("PORT", "5003"));
        SpringApplication.run(SampleApp.class, args);
    }

    private static String client(HttpServletRequest r) {
        Span.current().setAttribute("client.address", r.getRemoteAddr());
        return r.getRemoteAddr();
    }

    @GetMapping("/health")
    public Map<String, Object> health() { return Map.of("ok", true); }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> body, HttpServletRequest r) {
        String user = body.getOrDefault("user", ""), pw = body.getOrDefault("password", "");
        String c = client(r);
        if ("alice".equals(user) && "correct-horse".equals(pw)) {
            OwSecurity.login("success", user, c, "/login");
            return ResponseEntity.ok(Map.of("token", "demo-token"));
        }
        OwSecurity.login("failure", user, c, "/login");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid credentials"));
    }

    @GetMapping("/orders/{orderId}")
    public Map<String, Object> order(@PathVariable long orderId, HttpServletRequest r) {
        client(r);
        return Map.of("id", orderId, "status", "shipped");
    }

    @GetMapping("/search")
    public Map<String, Object> search(@RequestParam(defaultValue = "") String q, HttpServletRequest r) {
        String c = client(r);
        String l = q.toLowerCase();
        if (q.contains("'") || q.contains("--") || l.contains(" or ")) {
            OwSecurity.inputRejected("sqli", "/search", "q", c);
            throw new SqlSyntaxException("syntax error near the supplied search text");
        }
        return Map.of("results", new Object[0]);
    }

    /** Intentionally vulnerable: runs a command given by the caller (rule APP-H01 should fire). */
    @GetMapping("/debug/exec")
    public Map<String, Object> exec(@RequestParam(defaultValue = "id") String cmd, HttpServletRequest r) throws Exception {
        client(r);
        Process p = new ProcessBuilder("/bin/sh", "-c", cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readNBytes(500));
        p.waitFor();
        return Map.of("output", out);
    }

    @ExceptionHandler(SqlSyntaxException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Map<String, Object> handle(SqlSyntaxException e) {
        Span.current().recordException(e); // exception.type = ng.obsidianwatch.sample.SampleApp$SqlSyntaxException
        return Map.of("error", e.getMessage());
    }
}
