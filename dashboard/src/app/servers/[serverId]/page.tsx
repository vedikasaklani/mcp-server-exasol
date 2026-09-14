import { ServerDetail } from "./ServerDetail";

export default async function Page(props: PageProps<"/servers/[serverId]">) {
  const { serverId } = await props.params;
  return <ServerDetail serverId={serverId} />;
}
