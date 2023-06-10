package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/golang/protobuf/ptypes/any"
	any2 "github.com/golang/protobuf/ptypes/any"

	"github.com/golang/protobuf/ptypes"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	testv3 "github.com/envoyproxy/go-control-plane/pkg/test/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimeservice "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretservice "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	partner "github.com/vijay-dcrust/envoyproxy/xds/control-plane/partner"
	sds "github.com/vijay-dcrust/envoyproxy/xds/control-plane/sds"
)

// This is mostly copied from
// https://github.com/envoyproxy/go-control-plane/tree/master/internal/example
// // Copyright 2020 Envoyproxy Authors

const (
	// don't use dots in resource name
	// ClusterName1  = "cluster_a"
	// ClusterName2  = "cluster_b"
	RouteName    = "local_route"
	ListenerName = "listener_0"
	//ListenerPort = 10000
	// UpstreamHost  = "127.0.0.1"
	// UpstreamPort1 = 8080
	// UpstreamPort2 = 8081

	xdsPort                  = 9977
	grpcMaxConcurrentStreams = 1000000
)

func makeCluster(clusterName string, destinationHost string, upstreamPort int) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       ptypes.DurationProto(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		LoadAssignment:       makeEndpoint(clusterName, destinationHost, upstreamPort),
		DnsLookupFamily:      cluster.Cluster_V4_ONLY,
	}
}

func makeEndpoint(clusterName string, destinationHost string, upstreamPort int) *endpoint.ClusterLoadAssignment {
	port := uint32(upstreamPort)
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: []*endpoint.LbEndpoint{{
				HostIdentifier: &endpoint.LbEndpoint_Endpoint{
					Endpoint: &endpoint.Endpoint{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Protocol: core.SocketAddress_TCP,
									Address:  destinationHost,
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: port,
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

func makeRoute(routeName string, clusterName string, destinationHost string) *route.RouteConfiguration {
	routeConfiguration := &route.RouteConfiguration{
		Name: routeName,
		VirtualHosts: []*route.VirtualHost{{
			Name:    clusterName,
			Domains: []string{"*"},
		}},
	}
	// switch weight {
	// case 0:
	routeConfiguration.VirtualHosts[0].Routes = []*route.Route{{
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{
				Prefix: "/",
			},
		},
		Action: &route.Route_Route{
			Route: &route.RouteAction{
				ClusterSpecifier: &route.RouteAction_Cluster{
					Cluster: clusterName,
				},
				HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
					HostRewriteLiteral: destinationHost,
				},
			},
		},
	}}

	return routeConfiguration
}

func makeHTTPListener(listenerName string, route string, listenerPort int) *listener.Listener {
	// HTTP filter configuration
	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "http",
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    makeConfigSource(),
				RouteConfigName: route,
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name: wellknown.Router,
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: &any2.Any{
					TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
				},
			},
		}},
	}
	pbst, err := ptypes.MarshalAny(manager)
	if err != nil {
		panic(err)
	}
	downstreamTlsContextBytes, err := proto.Marshal(sds.CreateDownStreamContext())
	if err != nil {
		panic(err)
	}

	filterChainMatch := &listener.FilterChainMatch{
		ServerNames: []string{"localhost", "host.docker.internal"},
	}
	listener := &listener.Listener{
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: uint32(listenerPort),
					},
				},
			},
		},
		ListenerFilters: []*listener.ListenerFilter{
			{
				Name: "envoy.filters.listener.tls_inspector",
				ConfigType: &listener.ListenerFilter_TypedConfig{
					TypedConfig: &any.Any{
						TypeUrl: "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector",
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: wellknown.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
			TransportSocket: &core.TransportSocket{
				Name: "tls",
				ConfigType: &core.TransportSocket_TypedConfig{
					TypedConfig: &any.Any{
						TypeUrl: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
						Value:   downstreamTlsContextBytes,
					},
				},
			},
		}},
	}
	listener.FilterChains[0].FilterChainMatch = filterChainMatch
	return listener
}

func makeConfigSource() *core.ConfigSource {
	source := &core.ConfigSource{}
	source.ResourceApiVersion = resource.DefaultAPIVersion
	source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &core.ApiConfigSource{
			TransportApiVersion:       resource.DefaultAPIVersion,
			ApiType:                   core.ApiConfigSource_GRPC,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*core.GrpcService{{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "xds_cluster"},
				},
			}},
		},
	}
	return source
}

var (
	version int
)

func GenerateSnapshot(weight uint32, clusterName []string, destinationHost []string, upstreamPort []int) (*cachev3.Snapshot, error) {
	version++
	// var secrets []types.Resource
	// for _, s := range sds.CreateSecret() {
	// 	secrets = append(secrets, s)
	// }
	// Create a new resources map to store the clusters
	//listenerNameList := []string{"listener_0", "listener_1"}
	//listenerPortList := []int{10000, 10001}
	firstlistenerPort := 9999
	//routeNameList := []string{"local_route_1", "local_route_2"}
	//virtualHostNameList := []string{"local_service_1", "local_service_2"}
	var clustersResources []types.Resource
	var routeResources []types.Resource
	var listenerResources []types.Resource
	for i, config := range clusterName {
		firstlistenerPort++
		clusterObj := makeCluster(config, destinationHost[i], upstreamPort[i])
		routeObj := makeRoute(config, config, destinationHost[i])
		listenerObj := makeHTTPListener(config, config, firstlistenerPort)
		listenerResources = append(listenerResources, listenerObj)

		// Add the cluster to the snapshot
		clustersResources = append(clustersResources, clusterObj)
		routeResources = append(routeResources, routeObj)
	}
	// listenerObj := makeHTTPListener("listener_0", "local_route_1", 10000)
	// listenerResources = append(listenerResources, listenerObj)

	nextversion := fmt.Sprintf("snapshot-%d", version)
	fmt.Println("publishing version: ", nextversion)
	snapshot, err := cachev3.NewSnapshot(
		nextversion, // version needs to be different for different snapshots
		map[resource.Type][]types.Resource{
			resource.EndpointType: {},
			resource.ClusterType:  clustersResources,
			//makeCluster(clusterName, destinationHost, upstreamPort),
			resource.RouteType:    routeResources,
			resource.ListenerType: listenerResources,
			//{
			// 	makeHTTPListener(ListenerName, routeNameList[0], 10000),
			// },
			resource.RuntimeType: {},
			resource.SecretType:  {},
		},
	)

	return snapshot, err
}

func registerServer(grpcServer *grpc.Server, server serverv3.Server) {
	// register services
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, server)
	clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, server)
	routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, server)
	listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, server)
	secretservice.RegisterSecretDiscoveryServiceServer(grpcServer, server)
	runtimeservice.RegisterRuntimeDiscoveryServiceServer(grpcServer, server)
}

// RunServer starts an xDS server at the given port.
func RunServer(ctx context.Context, srv3 serverv3.Server, port uint) {
	// gRPC golang library sets a very small upper bound for the number gRPC/h2
	// streams over a single TCP connection. If a proxy multiplexes requests over
	// a single connection to the management server, then it might lead to
	// availability problems.
	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions, grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams))
	grpcServer := grpc.NewServer(grpcOptions...)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}

	registerServer(grpcServer, srv3)

	log.Printf("management server listening on %d\n", port)
	if err = grpcServer.Serve(lis); err != nil {
		log.Println(err)
	}
}

type ClusterNodeHasher struct{}

// ID uses the node ID field
func (ClusterNodeHasher) ID(node *core.Node) string {
	if node == nil {
		return ""
	}
	return node.Cluster
}

func main() {
	ctx := context.Background()

	logger, _ := zap.NewProduction()
	defer logger.Sync() // flushes buffer, if any
	l := logger.Sugar()

	nodeGroup := "edge-gateway"

	// Create a cache
	cache := cachev3.NewSnapshotCache(false, ClusterNodeHasher{}, l)

	// Create the snapshot that we'll serve to Envoy
	partnerList, err := partner.GetPartnerList()
	if err != nil {
		log.Fatalf(err.Error())
	}
	var clusterNameList []string
	var destinationHostList []string
	var portList []int
	for _, partner := range partnerList {
		clusterNameList = append(clusterNameList, partner.Name)
		destinationHostList = append(destinationHostList, partner.Destination)
		portList = append(portList, partner.Dest_Port)
	}
	// clusterName := partnerList[0].Name
	// destinationHost := partnerList[0].Destination
	upstreamPort := partnerList[0].Dest_Port
	fmt.Printf("Upstream Port value %d", upstreamPort)

	snapshot, err := GenerateSnapshot(0, clusterNameList, destinationHostList, portList)
	if err != nil {
		l.Errorf("could not generate snapshot: %+v", err)
		os.Exit(1)
	}
	if err := snapshot.Consistent(); err != nil {
		l.Errorf("snapshot inconsistency: %+v\n%+v", snapshot, err)
		os.Exit(1)
	}
	l.Debugf("will serve snapshot %+v", snapshot)

	// Add the snapshot to the cache
	if err := cache.SetSnapshot(ctx, nodeGroup, snapshot); err != nil {
		l.Errorf("snapshot error %q for %+v", err, snapshot)
		os.Exit(1)
	}

	snapshot, err = GenerateSnapshot(0, clusterNameList, destinationHostList, portList)
	if err != nil {
		l.Errorf("could not generate snapshot: %+v", err)
		os.Exit(1)
	}
	if err := snapshot.Consistent(); err != nil {
		l.Errorf("snapshot inconsistency: %+v\n%+v", snapshot, err)
		os.Exit(1)
	}
	l.Debugf("will serve snapshot %+v", snapshot)

	// Add the snapshot to the cache
	if err := cache.SetSnapshot(ctx, nodeGroup, snapshot); err != nil {
		l.Errorf("snapshot error %q for %+v", err, snapshot)
		os.Exit(1)
	}

	// Run the xDS server
	cb := &testv3.Callbacks{Debug: true}
	srv := serverv3.NewServer(ctx, cache, cb)
	go RunServer(ctx, srv, xdsPort)
	// for {
	// 	for i, partner := range partnerList {
	// 		if i == 0 {
	// 			continue
	// 		}
	// 		clusterName := partner.Name
	// 		destinationHost := partner.Destination
	// 		upstreamPort := partner.Dest_Port
	// 		fmt.Printf("Upstream Port value %d", upstreamPort)

	// 		snapshot, err := GenerateSnapshot(0, clusterName, destinationHost, upstreamPort)
	// 		if err != nil {
	// 			l.Errorf("could not generate snapshot: %+v", err)
	// 			os.Exit(1)
	// 		}
	// 		if err := snapshot.Consistent(); err != nil {
	// 			l.Errorf("snapshot inconsistency: %+v\n%+v", snapshot, err)
	// 			os.Exit(1)
	// 		}
	// 		l.Debugf("will serve snapshot %+v", snapshot)
	// 		// Add the snapshot to the cache
	// 		if err := cache.SetSnapshot(ctx, nodeGroup, snapshot); err != nil {
	// 			l.Errorf("snapshot error %q for %+v", err, snapshot)
	// 			os.Exit(1)
	// 		}

	// 	}
	//
	// }
	time.Sleep(1000 * time.Second)
}
