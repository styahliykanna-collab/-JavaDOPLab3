package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

public class Main {

    public static void main(String[] args) {
        SecurityLogAnalyzer analyzer = new SecurityLogAnalyzer();

        LocalDateTime start =
                LocalDateTime.of(2026, 11, 22, 12, 0);

        // 1. Пошук першої критичної події
        AtomicInteger counter = new AtomicInteger();

        Stream<SecurityLog> criticalStream =
                Stream.generate(() -> {
                    int n = counter.incrementAndGet();

                    return new SecurityLog(
                            "192.168.1." + n,
                            n == 5 ? "CRITICAL" : "INFO",
                            "Security event " + n,
                            start.plusSeconds(n)
                    );
                });

        Optional<SecurityLog> critical =
                analyzer.findFirstCriticalEvent(criticalStream);

        System.out.println("=== FIRST CRITICAL EVENT ===");

        critical.ifPresentOrElse(
                log -> System.out.println(
                        "Found: " + log),
                () -> System.out.println("Not found")
        );

        // 2. Отримання логів до дедлайну
        Stream<SecurityLog> timeStream =
                Stream.iterate(
                        0,
                        n -> n + 1
                ).map(n -> new SecurityLog(
                        "10.0.0.1",
                        "INFO",
                        "Event " + n,
                        start.plusMinutes(n)
                ));

        System.out.println("\n=== LOGS BEFORE DEADLINE ===");

        analyzer.getLogsBeforeDeadline(
                timeStream,
                start.plusMinutes(5)
        ).forEach(System.out::println);

        // 3. Виявлення Burst-атак
        AtomicInteger burstCounter = new AtomicInteger();

        Stream<SecurityLog> burstStream =
                Stream.generate(() -> {
                    int n = burstCounter.getAndIncrement();
                    String ip = (n / 4) % 2 == 0
                            ? "192.168.1.100"
                            : "10.0.0.50";

                    return new SecurityLog(
                            ip,
                            "WARNING",
                            "Login attempt " + n,
                            start.plusSeconds(n)
                    );
                });

        System.out.println("\n=== IP BURST DETECTION ===");

        analyzer.detectIpBursts(
                burstStream,
                3,
                4
        ).forEach(ip ->
                System.out.println("Detected burst: " + ip)
        );
    }
}
