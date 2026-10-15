import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

type ScanResponse = {
  id: number;
  url: string;
  normalized_url?: string;
  score: number;
  created_at: string;
  ml_proba?: number | null;
  llm_summary?: string | null;
};

const API_BASE =
  Platform.OS === "android" ? "http://10.0.2.2:8000" : "http://localhost:8000";

export default function HomeScreen() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [typedSummary, setTypedSummary] = useState("");
  const [error, setError] = useState<string | null>(null);

  const scan = async () => {
    const u = url.trim();

    if (!u) {
      setResult(null);
      setTypedSummary("");
      setError("URL을 입력하세요.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setTypedSummary("");

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: u }),
      });

      const raw = await res.text();

      if (!res.ok) {
        setResult(null);
        setTypedSummary("");
        setError(raw || `검사 실패: HTTP ${res.status}`);
        return;
      }

      const data = raw ? (JSON.parse(raw) as ScanResponse) : null;

      if (!data) {
        setResult(null);
        setTypedSummary("");
        setError("검사 결과가 비어 있습니다.");
        return;
      }

      setResult(data);
    } catch (e) {
      setResult(null);
      setTypedSummary("");
      setError(e instanceof Error ? e.message : "검사 중 오류가 발생했습니다.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const summary = result?.llm_summary || "";

    setTypedSummary("");

    if (!summary) return;

    const chars = Array.from(summary);
    let index = 0;

    const timer = setInterval(() => {
      index += 1;
      setTypedSummary(chars.slice(0, index).join(""));

      if (index >= chars.length) {
        clearInterval(timer);
      }
    }, 28);

    return () => clearInterval(timer);
  }, [result?.llm_summary]);

  const pct = result?.score != null ? result.score : null;

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "left", "right"]}>
      <ScrollView contentContainerStyle={styles.container}>
      <View style={styles.card}>
        <Text style={styles.title}>악성 URL 검사</Text>
        <Text style={styles.subtitle}>
          URL을 입력하면 최종 위험도와 AI 요약을 확인할 수 있습니다.
        </Text>

        <View style={styles.inputBox}>
          <Text style={styles.label}>URL 입력</Text>

          <TextInput
            value={url}
            onChangeText={setUrl}
            onSubmitEditing={scan}
            autoCapitalize="none"
            autoCorrect={false}
            autoComplete="off"
            placeholder="https://example.com"
            style={styles.input}
            returnKeyType="done"
            blurOnSubmit={false}
            editable={!loading}
          />

          <Pressable
            style={[styles.button, loading && styles.buttonDisabled]}
            onPress={scan}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color="#ffffff" />
            ) : (
              <Text style={styles.buttonText}>검사하기</Text>
            )}
          </Pressable>
        </View>

        {error ? <Text style={styles.errorText}>{error}</Text> : null}

        <View style={styles.resultBox}>
          <Text style={styles.bigPct}>{pct == null ? "-" : `${pct}%`}</Text>
          <Text style={styles.muted}>위험도</Text>

          {loading ? (
            <Text style={styles.loadingText}>분석 중입니다...</Text>
          ) : null}

          {result?.llm_summary ? (
            <View style={styles.summaryBox}>
              <Text style={styles.summaryTitle}>AI 요약</Text>
              <Text style={styles.summaryText}>{typedSummary}</Text>
            </View>
          ) : null}

          {result?.normalized_url ? (
            <Text style={styles.urlText}>{result.normalized_url}</Text>
          ) : null}
        </View>
      </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: "#f8fafc",
  },
  container: {
    flexGrow: 1,
    backgroundColor: "#f8fafc",
    padding: 16,
    justifyContent: "center",
  },
  card: {
    padding: 16,
    borderWidth: 1,
    borderRadius: 18,
    borderColor: "#e2e8f0",
    backgroundColor: "#ffffff",
    gap: 14,
  },
  title: {
    fontSize: 24,
    fontWeight: "900",
    color: "#0f172a",
  },
  subtitle: {
    fontSize: 13,
    lineHeight: 19,
    color: "#64748b",
  },
  inputBox: {
    gap: 10,
  },
  label: {
    fontWeight: "800",
    color: "#334155",
  },
  input: {
    borderWidth: 1,
    borderColor: "#cbd5e1",
    borderRadius: 12,
    paddingHorizontal: 12,
    paddingVertical: 12,
    fontSize: 15,
    color: "#0f172a",
    backgroundColor: "#ffffff",
  },
  button: {
    height: 46,
    borderRadius: 12,
    backgroundColor: "#0f172a",
    alignItems: "center",
    justifyContent: "center",
  },
  buttonDisabled: {
    opacity: 0.65,
  },
  buttonText: {
    color: "#ffffff",
    fontWeight: "900",
    fontSize: 15,
  },
  errorText: {
    padding: 11,
    borderRadius: 12,
    backgroundColor: "#fff1f2",
    borderWidth: 1,
    borderColor: "#fecdd3",
    color: "#be123c",
    fontWeight: "700",
  },
  resultBox: {
    marginTop: 4,
    padding: 18,
    borderWidth: 1,
    borderColor: "#e2e8f0",
    borderRadius: 16,
    alignItems: "center",
    gap: 6,
    backgroundColor: "#f8fafc",
  },
  bigPct: {
    fontSize: 48,
    fontWeight: "900",
    color: "#0f172a",
  },
  muted: {
    color: "#64748b",
    fontWeight: "900",
  },
  loadingText: {
    marginTop: 8,
    fontSize: 13,
    color: "#64748b",
    fontWeight: "700",
  },
  summaryBox: {
    width: "100%",
    marginTop: 12,
    padding: 13,
    borderRadius: 14,
    backgroundColor: "#ffffff",
    borderWidth: 1,
    borderColor: "#e2e8f0",
  },
  summaryTitle: {
    marginBottom: 6,
    fontSize: 12,
    fontWeight: "900",
    color: "#64748b",
  },
  summaryText: {
    fontSize: 14,
    lineHeight: 22,
    color: "#334155",
    fontWeight: "700",
  },
  urlText: {
    marginTop: 8,
    opacity: 0.65,
    fontSize: 12,
    lineHeight: 17,
    textAlign: "center",
    color: "#334155",
  },
});