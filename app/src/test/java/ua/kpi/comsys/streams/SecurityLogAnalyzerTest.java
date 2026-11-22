package ua.kpi.comsys.streams;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class SecurityLogAnalyzerTest {

    private final SecurityLogAnalyzer analyzer =
            new SecurityLogAnalyzer();

    private static final LocalDateTime BASE =
            LocalDateTime.of(2026, 11, 22, 12, 0);

    private SecurityLog log(String ip, String level, int minute) {
        return new SecurityLog(
                ip, level, "Test event", BASE.plusMinutes(minute)
        );
    }

    @Test
    @Timeout(2)
    void findsFirstCriticalInInfiniteStream() {
        AtomicInteger counter = new AtomicInteger();

        Stream<SecurityLog> stream = Stream.generate(() -> {
            int n = counter.incrementAndGet();
            return log("192.168.1.1",
                    n == 5 ? "CRITICAL" : "INFO", n);
        });

        Optional<SecurityLog> result =
                analyzer.findFirstCriticalEvent(stream);

        assertTrue(result.isPresent());
        assertEquals("CRITICAL",
                result.orElseThrow().severityLevel());
        assertEquals(5, counter.get());
    }

    @Test
    void returnsEmptyWhenNoCriticalEvent() {
        Optional<SecurityLog> result =
                analyzer.findFirstCriticalEvent(
                        Stream.of(
                                log("1.1.1.1", "INFO", 0),
                                log("1.1.1.2", "WARNING", 1)
                        )
                );

        assertTrue(result.isEmpty());
    }

    @Test
    @Timeout(2)
    void stopsAtDeadlineInInfiniteStream() {
        Stream<SecurityLog> stream =
                Stream.iterate(0, n -> n + 1)
                        .map(n -> log("10.0.0.1", "INFO", n));

        List<SecurityLog> result =
                analyzer.getLogsBeforeDeadline(
                        stream, BASE.plusMinutes(5)
                );

        assertEquals(5, result.size());
        assertEquals(BASE.plusMinutes(4),
                result.getLast().timestamp());
    }

    @Test
    void stopsExactlyAtDeadline() {
        List<SecurityLog> result =
                analyzer.getLogsBeforeDeadline(
                        Stream.of(
                                log("1.1.1.1", "INFO", 0),
                                log("1.1.1.1", "INFO", 1)
                        ),
                        BASE.plusMinutes(1)
                );

        assertEquals(1, result.size());
    }

    @Test
    @Timeout(2)
    void detectsBurstsInInfiniteStream() {
        AtomicInteger counter = new AtomicInteger();

        Stream<SecurityLog> stream = Stream.generate(() -> {
            int n = counter.getAndIncrement();

            String ip = (n / 4) % 2 == 0
                    ? "192.168.1.100"
                    : "10.0.0.50";

            return log(ip, "WARNING", n);
        });

        List<String> result =
                analyzer.detectIpBursts(stream, 3, 4);

        assertEquals(List.of(
                "192.168.1.100",
                "10.0.0.50",
                "192.168.1.100",
                "10.0.0.50"
        ), result);
    }

    @Test
    void doesNotReportShortBursts() {
        List<String> result = analyzer.detectIpBursts(
                Stream.of(
                        log("A", "INFO", 0),
                        log("A", "INFO", 1),
                        log("B", "INFO", 2),
                        log("B", "INFO", 3)
                ), 3, 2
        );

        assertTrue(result.isEmpty());
    }

    @Test
    void reportsEachBurstOnlyOnce() {
        List<String> result = analyzer.detectIpBursts(
                Stream.of(
                        log("A", "INFO", 0),
                        log("A", "INFO", 1),
                        log("A", "INFO", 2),
                        log("A", "INFO", 3),
                        log("A", "INFO", 4)
                ), 3, 5
        );

        assertEquals(List.of("A"), result);
    }

    @Test
    void rejectsNullArguments() {
        assertThrows(IllegalArgumentException.class,
                () -> analyzer.findFirstCriticalEvent(null));

        assertThrows(IllegalArgumentException.class,
                () -> analyzer.getLogsBeforeDeadline(null, BASE));

        assertThrows(IllegalArgumentException.class,
                () -> analyzer.getLogsBeforeDeadline(
                        Stream.empty(), null));

        assertThrows(IllegalArgumentException.class,
                () -> analyzer.detectIpBursts(null, 3, 2));
    }

    @Test
    void rejectsInvalidBurstParameters() {
        assertThrows(IllegalArgumentException.class,
                () -> analyzer.detectIpBursts(
                        Stream.empty(), 0, 2));

        assertThrows(IllegalArgumentException.class,
                () -> analyzer.detectIpBursts(
                        Stream.empty(), 3, 0));

        assertThrows(IllegalArgumentException.class,
                () -> analyzer.detectIpBursts(
                        Stream.empty(), -1, -1));
    }

    @Test
    void detectsBurstWithThresholdOne() {
        List<String> result = analyzer.detectIpBursts(
                Stream.of(
                        log("A", "INFO", 0),
                        log("B", "INFO", 1)
                ), 1, 2
        );

        assertEquals(List.of("A", "B"), result);
    }
}
