/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.access;

import java.util.Collection;

import org.springframework.security.core.Authentication;

/**
 * 投票器接口
 * 针对某一个操作进行投票,决定是否允许当前操作
 *
 *
 * Indicates a class is responsible for voting on authorization decisions.
 * <p>
 * The coordination of voting (ie polling {@code AccessDecisionVoter}s, tallying their
 * responses, and making the final authorization decision) is performed by an
 * {@link org.springframework.security.access.AccessDecisionManager}.
 *
 * @author Ben Alex
 */
public interface AccessDecisionVoter<S> {

	// 投票通过
	int ACCESS_GRANTED = 1;

	// 弃权
	int ACCESS_ABSTAIN = 0;

	// 拒绝
	int ACCESS_DENIED = -1;

	/**
	 * 判断是否支持处理 ConfigAttribute 对象
	 *
	 * Indicates whether this {@code AccessDecisionVoter} is able to vote on the passed
	 * {@code ConfigAttribute}.
	 * <p>
	 * This allows the {@code AbstractSecurityInterceptor} to check every configuration
	 * attribute can be consumed by the configured {@code AccessDecisionManager} and/or
	 * {@code RunAsManager} and/or {@code AfterInvocationManager}.
	 * @param attribute a configuration attribute that has been configured against the
	 * {@code AbstractSecurityInterceptor}
	 * @return true if this {@code AccessDecisionVoter} can support the passed
	 * configuration attribute
	 */
	boolean supports(ConfigAttribute attribute);

	/**
	 * 判断是否支持处理受保护的安全对象
	 *
	 * Indicates whether the {@code AccessDecisionVoter} implementation is able to provide
	 * access control votes for the indicated secured object type.
	 * @param clazz the class that is being queried
	 * @return true if the implementation can process the indicated class
	 */
	boolean supports(Class<?> clazz);

	/**
	 * Indicates whether or not access is granted.
	 * <p>
	 * The decision must be affirmative ({@code ACCESS_GRANTED}), negative (
	 * {@code ACCESS_DENIED}) or the {@code AccessDecisionVoter} can abstain (
	 * {@code ACCESS_ABSTAIN}) from voting. Under no circumstances should implementing
	 * classes return any other value. If a weighting of results is desired, this should
	 * be handled in a custom
	 * {@link org.springframework.security.access.AccessDecisionManager} instead.
	 * <p>
	 * Unless an {@code AccessDecisionVoter} is specifically intended to vote on an access
	 * control decision due to a passed method invocation or configuration attribute
	 * parameter, it must return {@code ACCESS_ABSTAIN}. This prevents the coordinating
	 * {@code AccessDecisionManager} from counting votes from those
	 * {@code AccessDecisionVoter}s without a legitimate interest in the access control
	 * decision.
	 * <p>
	 * Whilst the secured object (such as a {@code MethodInvocation}) is passed as a
	 * parameter to maximise flexibility in making access control decisions, implementing
	 * classes should not modify it or cause the represented invocation to take place (for
	 * example, by calling {@code MethodInvocation.proceed()}).
	 *
	 * @param authentication 可以提取出当前用户所具备的权限
	 * @param object 受保护的安全对象；如果是 URL 地址,Object 就是一个 FilterInvocation；如果是一个方法,object 就是一个 MethodInvocation 对象
	 * @param attributes 表示访问受保护对象所需要的权限
	 * @return either {@link #ACCESS_GRANTED}, {@link #ACCESS_ABSTAIN} or
	 *
	 * 具体的投票方法,根据用户所具有的权限以及当前请求需要的权限进行投票
	 *
	 *
	 * {@link #ACCESS_DENIED}
	 */
	int vote(Authentication authentication, S object, Collection<ConfigAttribute> attributes);

}
