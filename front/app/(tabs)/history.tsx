import React, { useCallback, useMemo, useState } from "react";
import {
  ActivityIndicator,
  FlatList,
  Platform,
  Pressable,
  RefreshControl,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useFocusEffect } from "expo-router";

const API_BASE =
  Platform.OS === "android" ? "http://10.0.2.2:8000" : "http://localhost:8000";

type Verdict = "safe" | "suspicious" | "malicious";
type VerdictFilter = "all" | Verdict;

type UrlTypeItem = {
  type?: string;
  score?: number;
  reasons?: string[];
};

type ScanFeatures = {
  url_type?: string;
  url_type_reasons?: string[];
  url_types?: UrlTypeItem[];

  has_http?: number;
  has_ip?: number;
  has_at?: number;
  is_shortener?: number;
  has_punycode?: number;
  suspicious_tld?: number;
  path_has_login_like?: number;
  keyword_hit_count?: number;
  query_param_count?: number;
  query_len?: number;
  url_len?: number;
  host_hyphen_count?: number;
  subdomain_depth?: number;
  host_dot_count?: number;
  sm_final_host_changed?: number;
  brand_hit_count?: number;
  digit_ratio?: number;
  host_digit_ratio?: number;

  virustotal?: {
    ok?: boolean;
    found?: boolean;
    malicious?: number;
    suspicious?: number;
    harmless?: number;
    undetected?: number;
  };

  vt_model_summary?: {
    case?: string;
    message?: string;
    model_score?: number;
    vt_score?: number;
    final_score?: number;
  };

  [key: string]: unknown;
};

type ScanItem = {
  id: number;
  url: string;
  normalized_url?: string;
  score: number;
  verdict: Verdict;
  reason?: string;
  reason_details?: string[];
  features?: ScanFeatures;
  created_at: string;
};

const FILTERS: { label: string; value: VerdictFilter }[] = [
  { label: "전체", value: "all" },
  { label: "안전", value: "safe" },
  { label: "주의", value: "suspicious" },
  { label: "위험", value: "malicious" },
];

const clampScore = (value?: number | null) => {
  const n = Number(value ?? 0);

  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 100) return 100;

  return Math.round(n);
};

const toNumber = (value: unknown) => {
  const n = Number(value ?? 0);
  return Number.isNaN(n) ? 0 : n;
};

const unique = (arr: string[]) => {
  return Array.from(new Set(arr.filter(Boolean)));
};

const getVerdictText = (value?: Verdict, score?: number) => {
  if (value === "safe") return "안전";
  if (value === "suspicious") return "주의";
  if (value === "malicious") return "위험";

  const s = clampScore(score);
  if (s >= 70) return "위험";
  if (s >= 40) return "주의";
  return "안전";
};

const getRiskStyles = (verdict?: Verdict, score?: number) => {
  const label = getVerdictText(verdict, score);

  if (label === "위험") {
    return {
      badge: styles.resultDanger,
      text: styles.resultDangerText,
      scoreBadge: styles.scoreDanger,
      scoreText: styles.scoreDangerText,
    };
  }

  if (label === "주의") {
    return {
      badge: styles.resultWarn,
      text: styles.resultWarnText,
      scoreBadge: styles.scoreWarn,
      scoreText: styles.scoreWarnText,
    };
  }

  return {
    badge: styles.resultSafe,
    text: styles.resultSafeText,
    scoreBadge: styles.scoreSafe,
    scoreText: styles.scoreSafeText,
  };
};

const formatDate = (value?: string) => {
  if (!value) return "-";

  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;

  return d.toLocaleString("ko-KR", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
};

const toErrText = (x: unknown) => {
  if (x == null) return "";
  if (typeof x === "string") return x;
  if (x instanceof Error) return x.message;

  try {
    return JSON.stringify(x);
  } catch {
    return String(x);
  }
};

const getUrlType = (item: ScanItem) => {
  const features = item.features || {};

  if (features.url_type && String(features.url_type).trim()) {
    return String(features.url_type);
  }

  const firstType = features.url_types?.[0]?.type;

  if (firstType && String(firstType).trim()) {
    return String(firstType);
  }

  return "일반 정보형";
};

const normalizeSignalTag = (reason?: string | null) => {
  const text = String(reason || "").trim();

  if (!text) return null;

  const lower = text.toLowerCase();

  // 내부 점수/디버그성 문구는 History에서 숨김
  if (
    lower.startsWith("dl=") ||
    lower.startsWith("cnn_score=") ||
    lower.startsWith("rule_score=") ||
    lower.startsWith("model_score=") ||
    lower.startsWith("vt_score=") ||
    lower.startsWith("final_score=") ||
    lower.startsWith("virustotal") ||
    lower.includes("version") ||
    lower.includes("prob")
  ) {
    return null;
  }

  if (text.includes("CNN 전체 URL 패턴 분석")) return "CNN 패턴";
  if (text.includes("HTTP 사용") || text.includes("암호화 미사용")) return "HTTP 사용";
  if (text.includes("IP 주소") || text.includes("IP 사용")) return "IP 직접 접근";
  if (text.includes("@")) return "@ 포함";
  if (text.includes("단축") || lower.includes("shortener")) return "단축 URL";
  if (lower.includes("punycode")) return "퓨니코드";
  if (text.includes("의심 TLD")) return "의심 TLD";
  if (text.includes("서브도메인") || text.includes("하위 도메인")) return "서브도메인 과다";
  if (text.includes("하이픈")) return "하이픈 과다";
  if (text.includes("쿼리 파라미터")) return "쿼리 과다";
  if (text.includes("쿼리 길이")) return "긴 쿼리";
  if (text.includes("URL 길이")) return "긴 URL";
  if (text.includes("숫자 비율")) return "숫자 비율 높음";
  if (text.includes("리다이렉트")) return "리다이렉트";
  if (text.includes("최종 도메인 변경")) return "도메인 변경";
  if (text.includes("브랜드")) return "브랜드 위장";
  if (text.includes("로그인") || lower.includes("login") || lower.includes("signin")) {
    return "로그인 유도";
  }
  if (text.includes("계정") || lower.includes("account") || lower.includes("verify")) {
    return "계정 확인";
  }
  if (
    text.includes("결제") ||
    lower.includes("payment") ||
    lower.includes("billing") ||
    lower.includes("card") ||
    lower.includes("wallet")
  ) {
    return "결제 유도";
  }
  if (
    text.includes("파일") ||
    lower.includes("download") ||
    lower.includes("document") ||
    lower.includes("file")
  ) {
    return "파일 다운로드";
  }
  if (text.includes("의심 키워드") || text.includes("관련 키워드")) return "의심 키워드";
  if (text.includes("VirusTotal 미탐지")) return "VT 미탐지";
  if (text.includes("VirusTotal") && text.includes("탐지")) return "VT 탐지";

  if (text.length > 16) return text.slice(0, 16);

  return text;
};

const getSignalTags = (item: ScanItem) => {
  const features = item.features || {};
  const tags: string[] = [];

  const add = (tag?: string | null) => {
    if (!tag) return;
    tags.push(tag);
  };

  // features 기반 신호
  if (toNumber(features.has_http) === 1) add("HTTP 사용");
  if (toNumber(features.has_ip) === 1) add("IP 직접 접근");
  if (toNumber(features.has_at) === 1) add("@ 포함");
  if (toNumber(features.is_shortener) === 1) add("단축 URL");
  if (toNumber(features.has_punycode) === 1) add("퓨니코드");
  if (toNumber(features.suspicious_tld) === 1) add("의심 TLD");
  if (toNumber(features.path_has_login_like) === 1) add("로그인 유도");
  if (toNumber(features.keyword_hit_count) >= 1) add("의심 키워드");
  if (toNumber(features.query_param_count) >= 3) add("쿼리 과다");
  if (toNumber(features.query_len) >= 80) add("긴 쿼리");
  if (toNumber(features.url_len) >= 120) add("긴 URL");
  if (toNumber(features.host_hyphen_count) >= 2) add("하이픈 과다");
  if (toNumber(features.subdomain_depth) >= 3 || toNumber(features.host_dot_count) >= 4) {
    add("서브도메인 과다");
  }
  if (toNumber(features.sm_final_host_changed) === 1) add("도메인 변경");
  if (toNumber(features.brand_hit_count) >= 1) add("브랜드 위장");
  if (toNumber(features.digit_ratio) >= 0.25 || toNumber(features.host_digit_ratio) >= 0.2) {
    add("숫자 비율 높음");
  }

  const vtMalicious = toNumber(features.virustotal?.malicious);
  const vtSuspicious = toNumber(features.virustotal?.suspicious);

  if (vtMalicious >= 1) add("VT 악성 탐지");
  else if (vtSuspicious >= 1) add("VT 의심 탐지");

  const fromType = Array.isArray(features.url_type_reasons)
    ? features.url_type_reasons
    : [];
  const fromTopType = Array.isArray(features.url_types?.[0]?.reasons)
    ? features.url_types?.[0]?.reasons || []
    : [];
  const fromDetails = Array.isArray(item.reason_details) ? item.reason_details : [];
  const fromReason = item.reason ? item.reason.split(";") : [];
  const fromSummary = features.vt_model_summary?.case
    ? [features.vt_model_summary.case]
    : [];

  [...fromType, ...fromTopType, ...fromDetails, ...fromReason, ...fromSummary].forEach(
    (value) => {
      add(normalizeSignalTag(value));
    }
  );

  const cleaned = unique(tags);

  if (cleaned.length > 0) {
    return cleaned.slice(0, 7);
  }

  return ["특이 신호 적음"];
};

function FilterChip({
  text,
  active,
  onPress,
}: {
  text: string;
  active: boolean;
  onPress: () => void;
}) {
  return (
    <Pressable
      onPress={onPress}
      style={[styles.filterChip, active && styles.filterChipActive]}
    >
      <Text
        style={[styles.filterChipText, active && styles.filterChipTextActive]}
      >
        {text}
      </Text>
    </Pressable>
  );
}

export default function HistoryScreen() {
  const [items, setItems] = useState<ScanItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<VerdictFilter>("all");

  const load = useCallback(async () => {
    setLoading(true);
    setErr(null);

    try {
      const params = new URLSearchParams();
      params.set("limit", "100");
      params.set("sort", "recent");
      if (filter !== "all") params.set("verdict", filter);

      const res = await fetch(`${API_BASE}/scans?${params.toString()}`);
      const raw = await res.text();

      if (!res.ok) {
        setErr(raw || `HTTP ${res.status}`);
        setItems([]);
        return;
      }

      const data = raw ? JSON.parse(raw) : [];
      setItems(Array.isArray(data) ? data : []);
    } catch (e: unknown) {
      setErr(toErrText(e));
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useFocusEffect(
    useCallback(() => {
      load();
    }, [load])
  );

  const summary = useMemo(() => {
    return {
      total: items.length,
      safe: items.filter((item) => item.verdict === "safe").length,
      suspicious: items.filter((item) => item.verdict === "suspicious").length,
      malicious: items.filter((item) => item.verdict === "malicious").length,
    };
  }, [items]);

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "left", "right"]}>
      <View style={styles.container}>
      <View style={styles.header}>
        <View style={styles.headerTextWrap}>
          <Text style={styles.title}>검사 기록</Text>
          <Text style={styles.subtitle}>
            이전에 검사한 URL의 위험도, 유형, 감지 신호를 확인할 수 있습니다.
          </Text>
        </View>

        <Pressable style={styles.reloadButton} onPress={load} disabled={loading}>
          <Text style={styles.reloadButtonText}>
            {loading ? "불러오는 중" : "새로고침"}
          </Text>
        </Pressable>
      </View>

      {err ? (
        <Text style={styles.errorText}>불러오기에 실패했습니다: {err}</Text>
      ) : null}

      <View style={styles.summaryRow}>
        <View style={styles.summaryCard}>
          <Text style={styles.summaryNumber}>{summary.total}</Text>
          <Text style={styles.summaryLabel}>전체</Text>
        </View>

        <View style={styles.summaryCard}>
          <Text style={styles.summaryNumber}>{summary.safe}</Text>
          <Text style={styles.summaryLabel}>안전</Text>
        </View>

        <View style={styles.summaryCard}>
          <Text style={styles.summaryNumber}>{summary.suspicious}</Text>
          <Text style={styles.summaryLabel}>주의</Text>
        </View>

        <View style={styles.summaryCard}>
          <Text style={styles.summaryNumber}>{summary.malicious}</Text>
          <Text style={styles.summaryLabel}>위험</Text>
        </View>
      </View>

      <View style={styles.filterBox}>
        <Text style={styles.filterTitle}>결과별 보기</Text>
        <View style={styles.filterRow}>
          {FILTERS.map((item) => (
            <FilterChip
              key={item.value}
              text={item.label}
              active={filter === item.value}
              onPress={() => setFilter(item.value)}
            />
          ))}
        </View>
      </View>

      <FlatList
        data={items}
        keyExtractor={(item) => String(item.id)}
        refreshControl={<RefreshControl refreshing={loading} onRefresh={load} />}
        contentContainerStyle={styles.listContent}
        ListEmptyComponent={
          <View style={styles.emptyBox}>
            {loading ? <ActivityIndicator /> : null}
            <Text style={styles.emptyText}>
              {loading ? "기록을 불러오는 중입니다." : "표시할 기록이 없습니다."}
            </Text>
          </View>
        }
        renderItem={({ item }) => {
          const score = clampScore(item.score);
          const url = item.normalized_url || item.url;
          const urlType = getUrlType(item);
          const verdictText = getVerdictText(item.verdict, score);
          const riskStyles = getRiskStyles(item.verdict, score);
          const signalTags = getSignalTags(item);

          return (
            <View style={styles.card}>
              <View style={styles.topRow}>
                <View style={[styles.scoreBadge, riskStyles.scoreBadge]}>
                  <Text style={[styles.scoreBadgeText, riskStyles.scoreText]}>
                    위험도 {score}%
                  </Text>
                </View>

                <View style={[styles.resultBadge, riskStyles.badge]}>
                  <Text style={[styles.resultBadgeText, riskStyles.text]}>
                    {verdictText}
                  </Text>
                </View>
              </View>

              <View style={styles.section}>
                <Text style={styles.sectionTitle}>검사한 주소</Text>
                <Text style={styles.urlText} numberOfLines={2}>
                  {url}
                </Text>
              </View>

              <View style={styles.metaRow}>
                <View style={styles.metaItem}>
                  <Text style={styles.sectionTitle}>유형</Text>
                  <Text style={styles.bodyText}>{urlType}</Text>
                </View>

                <View style={styles.metaItem}>
                  <Text style={styles.sectionTitle}>검사 시간</Text>
                  <Text style={styles.bodyText}>{formatDate(item.created_at)}</Text>
                </View>
              </View>

              <View style={styles.sectionLast}>
                <Text style={styles.sectionTitle}>감지 신호</Text>
                <View style={styles.signalWrap}>
                  {signalTags.map((tag, idx) => (
                    <View key={`${item.id}-${tag}-${idx}`} style={styles.signalChip}>
                      <Text style={styles.signalText}>{tag}</Text>
                    </View>
                  ))}
                </View>
              </View>
            </View>
          );
        }}
      />
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: "#f8fafc",
  },
  container: {
    flex: 1,
    backgroundColor: "#f8fafc",
    padding: 16,
  },
  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 12,
  },
  headerTextWrap: {
    flex: 1,
    paddingRight: 12,
  },
  title: {
    fontSize: 24,
    fontWeight: "800",
    color: "#0f172a",
  },
  subtitle: {
    marginTop: 4,
    fontSize: 13,
    color: "#64748b",
    lineHeight: 18,
  },
  reloadButton: {
    paddingVertical: 10,
    paddingHorizontal: 14,
    borderRadius: 12,
    backgroundColor: "#ffffff",
    borderWidth: 1,
    borderColor: "#cbd5e1",
  },
  reloadButtonText: {
    fontWeight: "700",
    color: "#0f172a",
  },
  errorText: {
    marginBottom: 12,
    padding: 12,
    borderRadius: 12,
    backgroundColor: "#fff1f2",
    color: "#be123c",
    borderWidth: 1,
    borderColor: "#fecdd3",
  },
  summaryRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    marginBottom: 12,
    gap: 8,
  },
  summaryCard: {
    flex: 1,
    minWidth: "22%",
    backgroundColor: "#ffffff",
    borderWidth: 1,
    borderColor: "#e2e8f0",
    borderRadius: 14,
    paddingVertical: 14,
    paddingHorizontal: 10,
  },
  summaryNumber: {
    fontSize: 20,
    fontWeight: "800",
    color: "#0f172a",
  },
  summaryLabel: {
    marginTop: 4,
    fontSize: 12,
    color: "#64748b",
  },
  filterBox: {
    backgroundColor: "#ffffff",
    borderWidth: 1,
    borderColor: "#e2e8f0",
    borderRadius: 16,
    padding: 12,
    marginBottom: 12,
  },
  filterTitle: {
    fontSize: 12,
    fontWeight: "800",
    color: "#64748b",
    marginBottom: 8,
  },
  filterRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  filterChip: {
    paddingVertical: 9,
    paddingHorizontal: 12,
    borderRadius: 999,
    backgroundColor: "#f8fafc",
    borderWidth: 1,
    borderColor: "#cbd5e1",
  },
  filterChipActive: {
    backgroundColor: "#0f172a",
    borderColor: "#0f172a",
  },
  filterChipText: {
    fontSize: 12,
    fontWeight: "700",
    color: "#334155",
  },
  filterChipTextActive: {
    color: "#ffffff",
  },
  listContent: {
    paddingBottom: 28,
  },
  emptyBox: {
    alignItems: "center",
    justifyContent: "center",
    paddingVertical: 40,
  },
  emptyText: {
    marginTop: 10,
    fontSize: 14,
    color: "#64748b",
  },
  card: {
    backgroundColor: "#ffffff",
    borderWidth: 1,
    borderColor: "#e2e8f0",
    borderRadius: 18,
    padding: 14,
    marginBottom: 12,
  },
  topRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 14,
    gap: 10,
  },
  scoreBadge: {
    paddingVertical: 7,
    paddingHorizontal: 11,
    borderRadius: 999,
  },
  scoreBadgeText: {
    fontWeight: "900",
    fontSize: 13,
  },
  scoreSafe: {
    backgroundColor: "#ecfdf5",
  },
  scoreSafeText: {
    color: "#047857",
  },
  scoreWarn: {
    backgroundColor: "#fff7ed",
  },
  scoreWarnText: {
    color: "#c2410c",
  },
  scoreDanger: {
    backgroundColor: "#fef2f2",
  },
  scoreDangerText: {
    color: "#b91c1c",
  },
  resultBadge: {
    paddingVertical: 7,
    paddingHorizontal: 11,
    borderRadius: 999,
  },
  resultSafe: {
    backgroundColor: "#ecfdf5",
  },
  resultWarn: {
    backgroundColor: "#fff7ed",
  },
  resultDanger: {
    backgroundColor: "#fef2f2",
  },
  resultBadgeText: {
    fontSize: 12,
    fontWeight: "900",
  },
  resultSafeText: {
    color: "#047857",
  },
  resultWarnText: {
    color: "#c2410c",
  },
  resultDangerText: {
    color: "#b91c1c",
  },
  section: {
    marginBottom: 12,
  },
  sectionLast: {
    marginBottom: 0,
  },
  sectionTitle: {
    fontSize: 12,
    fontWeight: "800",
    color: "#64748b",
    marginBottom: 5,
  },
  urlText: {
    fontSize: 15,
    fontWeight: "700",
    color: "#0f172a",
    lineHeight: 21,
  },
  bodyText: {
    fontSize: 14,
    color: "#334155",
    lineHeight: 20,
    fontWeight: "700",
  },
  metaRow: {
    flexDirection: "row",
    gap: 10,
    marginBottom: 12,
  },
  metaItem: {
    flex: 1,
    minWidth: 0,
  },
  signalWrap: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 6,
  },
  signalChip: {
    paddingVertical: 6,
    paddingHorizontal: 9,
    borderRadius: 999,
    backgroundColor: "#f1f5f9",
    borderWidth: 1,
    borderColor: "#e2e8f0",
  },
  signalText: {
    fontSize: 12,
    fontWeight: "800",
    color: "#334155",
  },
});