package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Gatherer;
import java.util.stream.Stream;

public class SecurityLogAnalyzer {

    // Знайти першу критичну подію
    public Optional<SecurityLog> findFirstCriticalEvent(
            Stream<SecurityLog> stream) {

        if (stream == null) {
            throw new IllegalArgumentException(
                    "Stream cannot be null");
        }

        return stream
                .filter(log -> "CRITICAL".equals(
                        log.severityLevel()))
                .findFirst();
    }

    // Отримати події до заданого дедлайну
    public List<SecurityLog> getLogsBeforeDeadline(
            Stream<SecurityLog> stream,
            LocalDateTime deadline) {

        if (stream == null || deadline == null) {
            throw new IllegalArgumentException(
                    "Stream and deadline cannot be null");
        }

        return stream
                .takeWhile(log ->
                        log.timestamp().isBefore(deadline))
                .toList();
    }

    // Виявити Burst-атаки за IP-адресами
    public List<String> detectIpBursts(
            Stream<SecurityLog> stream,
            int burstThreshold,
            int maxIpsToReport) {

        if (stream == null) {
            throw new IllegalArgumentException(
                    "Stream cannot be null");
        }

        if (burstThreshold <= 0 || maxIpsToReport <= 0) {
            throw new IllegalArgumentException(
                    "Threshold and limit must be positive");
        }

        class BurstState {
            String lastIp = null;
            int consecutiveCount = 0;
            int reportedCount = 0;
        }

        Gatherer<SecurityLog, BurstState, String> burstGatherer =
                Gatherer.ofSequential(
                        BurstState::new,
                        (state, log, downstream) -> {

                            String currentIp = log.ipAddress();

                            if (Objects.equals(
                                    state.lastIp, currentIp)) {
                                state.consecutiveCount++;
                            } else {
                                state.lastIp = currentIp;
                                state.consecutiveCount = 1;
                            }

                            if (state.consecutiveCount
                                    == burstThreshold) {

                                state.reportedCount++;

                                boolean accepted =
                                        downstream.push(currentIp);

                                return accepted
                                        && state.reportedCount
                                        < maxIpsToReport;
                            }

                            return true;
                        }
                );

        return stream
                .gather(burstGatherer)
                .limit(maxIpsToReport)
                .toList();
    }
}
