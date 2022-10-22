package kv51pwn

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang/groupcache"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

/*
Running 3 instances:
go run groupcache.go -addr=:8080 -pool=http://127.0.0.1:8080,http://127.0.0.1:8081,http://127.0.0.1:8082
go run groupcache.go -addr=:8081 -pool=http://127.0.0.1:8081,http://127.0.0.1:8080,http://127.0.0.1:8082
go run groupcache.go -addr=:8082 -pool=http://127.0.0.1:8082,http://127.0.0.1:8080,http://127.0.0.1:8081

若干个 peer 都在lan的时候，需要实现 p2p 穿透
*/
type GroupcacheImp struct {
	LocalPeer     string                      `json:"local_peer"`     // peers，也就是gin的服务器地址及端口
	ClusterServer *[]string                   `json:"cluster_server"` // cache集群节点
	CacheName     string                      `json:"cache_name"`     // 缓存name,可以为每个工具、每种扫描类型结果做一个二级缓存名
	Peers         *groupcache.HTTPPool        `json:"peers"`          // default "/_groupcache/"
	Ctx           *context.Context            `json:"ctx"`            //
	Handler       http.Handler                `json:"handler"`        // http://ip:group_addr/gckv/?k=xxx, 读取 xxx 的分布式值
	HttpServer    *gin.Engine                 `json:"http_server"`    //
	ConfigPath    string                      `json:"config_path"`    // /gckv/
	CacheOptions  *groupcache.HTTPPoolOptions `json:"cache_options"`  // 配置冗余等参数
	CaseByteSize  int64                       `json:"case_byte_size"` // default 500M, 500 * 1024 * 1024
	GetKey        func(k string) interface{}  `json:"get_key"`        // 获取索引数据
}

func NewGroupcacheImp() *GroupcacheImp {
	x2 := context.Background()
	x1 := &GroupcacheImp{
		LocalPeer:    "127.0.0.1:9001",
		Ctx:          &x2,
		ConfigPath:   "/gckv/",
		CacheName:    "51pwn",
		CaseByteSize: 500 * 1024 * 1024}
	// 重远程服务器加载所有可用节点
	x1.ClusterServer = &[]string{}
	//x1.Start()

	return x1
}

// 获取 key 的回调
//  这里 可以结合 bleve，用 bleve 实现存储
//  后期改造
func (r *GroupcacheImp) GetterFunc(ctx context.Context, key string, dest groupcache.Sink) (err error) {
	if nil != r.GetKey {
		if o := r.GetKey(key); nil != o {
			if data, err := json.Marshal(o); nil == err {
				dest.SetBytes(data)
			} else {
				return err
			}
		}
	}
	return errors.New("not set GetKey")
}

// 将ip:port转换成url的格式
func (r *GroupcacheImp) AddrsToUrl(node_list ...string) []string {
	urls := make([]string, len(node_list))
	for k, addr := range node_list {
		urls[k] = "https://" + addr
	}
	return urls
}

func (r *GroupcacheImp) Start() {
	r.SetUpGroup()
	// 本地peer
	r.Peers = groupcache.NewHTTPPool(r.AddrsToUrl(r.LocalPeer)[0])
	// 所有远端的分布式节点，可以采用其他 p2p 技术分发、加载
	r.SetPeers(*r.ClusterServer...)
	r.Handler = r.Peers
	// 注册peer的处理，挂在gin上
	r.HttpServer.Use(func(c *gin.Context) {
		r.Handler.ServeHTTP(c.Writer, c.Request)
	})
}

// 后期动态调整 peers
func (r *GroupcacheImp) SetPeers(peers ...string) {
	r.Peers.Set(r.AddrsToUrl(*r.ClusterServer...)...)
}

// 启动groupcache
//  1 << 20 = 1048576
func (g *GroupcacheImp) SetUpGroup() {
	// 缓存池
	stringGroup := groupcache.NewGroup(g.CacheName, g.CaseByteSize, groupcache.GetterFunc(g.GetterFunc))
	g.HttpServer.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, g.ConfigPath) {
			r := c.Request
			rw := c.Writer
			k := r.FormValue("k")

			var dest []byte
			fmt.Printf("look up for %s { %s } from groupcache\n", g.CacheName, k)
			if err := stringGroup.Get(*g.Ctx, k, groupcache.AllocatingByteSliceSink(&dest)); err != nil {
				rw.WriteHeader(http.StatusNotFound)
				rw.Write([]byte(err.Error()))
			} else {
				rw.WriteHeader(http.StatusOK)
				rw.Write(dest)
			}
		}
	})
}
