import { Tabs } from "expo-router";
import React from "react";
import { Text, useColorScheme } from "react-native";

const tabTint = {
  light: "#0f172a",
  dark: "#ffffff",
};

function TabIcon({ icon, color }: { icon: string; color: string }) {
  return <Text style={{ color, fontSize: 22, fontWeight: "900" }}>{icon}</Text>;
}

export default function TabLayout() {
  const colorScheme = useColorScheme();
  const activeTintColor = tabTint[colorScheme === "dark" ? "dark" : "light"];

  return (
    <Tabs
      screenOptions={{
        tabBarActiveTintColor: activeTintColor,
        headerShown: false,
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: "Home",
          tabBarIcon: ({ color }) => <TabIcon icon="⌂" color={color} />,
        }}
      />

      <Tabs.Screen
        name="history"
        options={{
          title: "History",
          tabBarIcon: ({ color }) => <TabIcon icon="↺" color={color} />,
        }}
      />
    </Tabs>
  );
}
