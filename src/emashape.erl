%%%-------------------------------------------------------------------
%%% @author Tristan Sloughter <>
%%% @copyright (C) 2012, Tristan Sloughter
%%% @doc
%%%
%%% @end
%%% Created : 14 Mar 2012 by Tristan Sloughter <>
%%%-------------------------------------------------------------------
-module(emashape).

-behaviour(gen_server).

%% API
-export([start_link/2,
         request/3,
         request/5,
         request/6]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include_lib("eunit/include/eunit.hrl").

-define(SERVER, ?MODULE). 

-record(state, {public_key, private_key}).

-type http_method() :: get | put | post | delete.
-type callback() :: function() | pid().
-type query_params() :: [{string(), string()}].
-type response() :: list() | binary().

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(PublicKey, PrivateKey) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [PublicKey, PrivateKey], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec request(Type :: http_method(), Url :: string(), Params :: query_params()) -> response().
request(Type, Url, Params) ->
    request(Type, Url, Params, true, true).

-spec request(Type :: http_method(), Url :: string(), Params :: query_params(),
              AddAuthHeaders :: boolean(), ParseJson :: boolean()) -> response().
request(Type, Url, Params, AddAuthHeaders, ParseJson) ->
    gen_server:call(?SERVER, {request, Type, Url, Params, AddAuthHeaders, ParseJson}).
    
-spec request(Type :: http_method(), Url :: string(), Params :: query_params(),
              AddAuthHeaders :: boolean(),  Callback :: callback(), ParseJson :: boolean()) -> response().
request(Type, Url, Params, AddAuthHeaders, Callback, ParseJson) ->
    gen_server:cast(?SERVER, {request, Type, Url, Params, AddAuthHeaders, Callback, ParseJson}).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([PublicKey, PrivateKey]) ->
    {ok, #state{public_key=PublicKey, private_key=PrivateKey}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({request, Type, Url, Params, AddAuthHeaders, ParseJson}, From, 
            State=#state{public_key=PublicKey, private_key=PrivateKey}) ->       
    proc_lib:spawn_link(fun() ->
                                Reply = in_request(Type, Url, Params, PublicKey, PrivateKey, AddAuthHeaders, ParseJson),
                                gen_server:reply(From, Reply)
                        end),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast({request, Type, Url, Params, AddAuthHeaders, Callback, ParseJson},
            State=#state{public_key=PublicKey, private_key=PrivateKey}) ->    
    proc_lib:spawn_link(fun() ->
                                Return = in_request(Type, Url, Params, PublicKey, PrivateKey, AddAuthHeaders, ParseJson),
                                run_callback(Callback, Return)
                        end),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

run_callback(Fun, Result) when is_function(Fun) ->
    Fun(Result);
run_callback(Pid, Result) when is_pid(Pid) ->
    Pid ! {result, Result}.

in_request(Type, Url, Params, PublicKey, PrivateKey, AddAuthHeaders, ParseJson) ->    
    Params2 = lists:ukeymerge(1, Params, get_qs_params(Url)),
    NewUrl = replace_qa_variables(Url, Params2),   
    Result = in_request(Type, NewUrl, Params2, PublicKey, PrivateKey, AddAuthHeaders),
    case ParseJson of
        true ->
            mochijson2:decode(Result);
        false ->
            Result
    end.   

in_request(Type, Url, Params, PublicKey, PrivateKey, AddAuthHeaders) ->    
    Headers = [{'Content-type', "application/x-www-form-urlencoded"} | client_headers()],
    Headers2 = case AddAuthHeaders of
                  true ->
                      AuthHeader = auth_header(PublicKey, PrivateKey),
                      [AuthHeader | Headers];
                  false ->
                      Headers
              end,

    Body = proplist_to_qs(Params),
    request_(Type, Url, Headers2, Body).

request_(get, Url, Headers, Body=[_|_]) ->
    request_(get, Url++"?"++Body, Headers, []);
request_(Type, Url, Headers, Body) ->
    Ssl = string:str(Url, "https") > 0 orelse string:str(Url, "443") > 0,
    {ok, _StatusCode, _ResponseHeaders, ResultBody} = ibrowse:send_req(Url, Headers, Type, Body, [{is_ssl, Ssl}]),
    ResultBody.

auth_header(PublicKey, PrivateKey) ->
    Uuid = ossp_uuid:make(v4, text), 
    UuidHash = crypto:sha_mac(PrivateKey, Uuid),   
    HexBin = list_to_binary(string:to_lower(lists:flatten([[integer_to_list(N1,16), integer_to_list(N2,16)] 
                                           || << N1:4, N2:4 >> <= UuidHash]))),
    { 'X-Mashape-Authorization', base64:encode_to_string(<<PublicKey/binary, ":", HexBin/binary, Uuid/binary>>) }.

client_headers() ->
    [{'X-Mashape-Language', "ERLANG"}, {'X-Mashape-Version', "V01"}].

proplist_to_qs(Params) ->   
    lists:flatten(lists:flatmap(fun({K, V}) ->
                                        io_lib:format("~s=~s&", [K, V])
                                end, Params)).

replace_qa_variables(Url, Params) ->
    lists:flatten(lists:foldl(fun({Key, Value}, Acc) ->
                      re:replace(Acc, "{"++ Key ++"}", Value, [{return, list}])
              end, Url, Params)).

get_qs_params(Url) ->
    [_, QS] = string:tokens(Url, "?"),
    [{K, V} || [K, V] <- [string:tokens(KV, "=") || KV <- string:tokens(QS, "&")]].    
        
%%%===================================================================
%%% Tests
%%%===================================================================

proplist_to_qs_test() ->
    ?assertEqual("hello=this&key=value&", proplist_to_qs([{hello, this}, {key, value}])).

replace_qa_variables_test() ->
    ?assertEqual("?name=Test&key=Value", replace_qa_variables("?name={name}&key={value}", 
                                                              [{"name", "Test"}, {"value", "Value"}])).
get_qs_params_test() ->
    ?assertEqual([{"key1", "value"}, {"key2", "value"}, {"key3", "{value3}"}],
                 get_qs_params("http://example.com?key1=value&key2=value&key3={value3}")).
